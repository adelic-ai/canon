"""Entity+window cross-model corroboration — behavioral detector joined to external rules at the grain
where they meet (same actor, same window), validated on a mechanism-modelled corpus with a negative control.

The negative control IS the "Kerberoasting without Rubeus" case: a non-Rubeus tool (Impacket) leaves the
intrinsic 4769 RC4 fan-out but no host artifact, so it must flag behaviorally and be corroborated by the
behavioral community rule while the Rubeus 4611 artifact stays absent (NONE, never FALSE).
"""

from pathlib import Path

import pytest

from detection._verdict import build_detection_root
from detection.cross_model import (
    SECURITY,
    cross_model_kerberoast,
    slice_entity_window,
    synthesize_kerberoast_corpus,
)
from detection.sigma_panel import SIGMA, corroborate

pytestmark = pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")


@pytest.fixture(scope="module")
def corpus():
    return synthesize_kerberoast_corpus()


def _fired(corpus, account):
    win = slice_entity_window(corpus, account, 0.0, 3600.0, entity_field="Account_Name", time_field="_sec")
    return [n for n, _f, _n in corroborate("T1558.003", win, SECURITY)["fired"]]


def test_behavioral_detector_discriminates_fan_out_from_normal(corpus):
    verdicts = cross_model_kerberoast(corpus)
    # exactly the two sweepers flag — not the 400 normals that also request RC4 tickets (the fan-out adds
    # the discrimination the per-event community rule lacks)
    assert len(verdicts) == 2
    assert all(v.to_contract()["decision"] == "true" for v in verdicts)
    assert all(v.to_contract()["guarantee"]["tier"] == "well_formed" for v in verdicts)


def test_rubeus_actor_corroborated_by_two_witnesses(corpus):
    rules = _fired(corpus, "svc_rubeus")
    assert any("kerberoasting_activity" in r for r in rules)   # behavioral (4769 RC4), tool-agnostic
    assert any("rubeus" in r for r in rules)                   # the Rubeus 4611 tool artifact


def test_kerberoasting_without_rubeus_still_corroborated_no_artifact(corpus):
    # the negative control: Impacket leaves the technique trace but no Rubeus artifact
    rules = _fired(corpus, "svc_impacket")
    assert any("kerberoasting_activity" in r for r in rules)   # technique confirmed
    assert not any("rubeus" in r for r in rules)               # tool NOT Rubeus — artifact absent, not refuted


def test_corroboration_is_recorded_on_the_verdict_provenance(corpus):
    verdicts = cross_model_kerberoast(corpus)
    cids = {v.provenance for v in verdicts}
    # rebuild svc_rubeus's root WITH its corroboration → CID is one of the emitted verdicts (the edge is
    # in the verdict's provenance); the SAME root WITHOUT corroboration has a different CID (not emitted)
    rules = _fired(corpus, "svc_rubeus")
    params = {"entity": "svc_rubeus", "bin": 0, "window": [0.0, 3600.0], "distinct_services": 18}
    corro = {"rules": rules, "votes": len(rules), "classes": 5,
             "technique": "T1558.003", "logsource": "windows/security"}
    ref = "kerberoast|svc_rubeus|0"
    assert build_detection_root(ref, params, corro).id in cids
    assert build_detection_root(ref, params, None).id not in cids
