"""Fidelity scorecard — does a compiled rule actually catch the labeled instance of its technique.

Gated on the OTRF corpus + Sigma rules: runs every evaluable T1003.001 rule against the labeled comsvcs
instance and asserts the honest shape — at least one rule catches it, most are silent (they target other
LSASS-dump variants), and the scorecard is explicit that only the labeled technique is measured.
"""

from pathlib import Path

import pytest

from detection.fidelity_scorecard import fidelity_scorecard, otrf_lsass_t1003_case, technique_fidelity
from detection.sigma_panel import SIGMA

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
pytestmark = pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()),
                                reason="OTRF corpus / SigmaHQ rules not present")


def test_technique_fidelity_on_the_labeled_comsvcs_instance():
    case = otrf_lsass_t1003_case(str(OTRF))
    assert case["positives"] and case["positives"][0] is not None        # the selector found the instance
    f = technique_fidelity("T1003.001", case["positives"],
                           corpus_id=case["corpus_id"], corpus_cid=case["corpus_cid"])
    assert f["rules_evaluable"] >= 5                                      # several rules claim T1003.001
    assert f["rules_catching"] >= 1                                       # the comsvcs rule (at least) catches it
    assert f["rules_silent"] >= 1                                         # most claim-but-miss this variant
    assert f["rules_catching"] + f["rules_silent"] == f["rules_evaluable"]
    assert 0.0 < f["catch_rate"] <= 1.0
    # the honest distinction: many silent rules are wrong-channel (missing-telemetry), not logic gaps; the
    # applicable-channel rate is the fair one and is >= the raw rate
    assert f["silent_causes"].get("missing-telemetry", 0) >= 1
    assert f["rules_applicable"] <= f["rules_evaluable"]
    assert f["catch_rate_applicable"] >= f["catch_rate"]
    # the comsvcs rule is among the catchers
    assert any("comsvcs" in a["rule"] and a["coverage"] == "true" for a in f["attestations"])


def test_scorecard_is_honest_about_scope():
    rep = fidelity_scorecard([otrf_lsass_t1003_case(str(OTRF))])
    assert rep["techniques_tested"] == ["T1003.001"]                     # only the labeled one is measured
    assert "T1003.001" in rep["per_technique"]
    assert "NONE" in rep["note"] and "dataset-generator" in rep["note"]   # explicit about the unlabeled rest
    assert len(rep["cid"]) == 64
