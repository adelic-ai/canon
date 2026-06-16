"""The Sigma panel wired into the cross_check axis as verdict enrichment.

The structural lsass-dump subgraph fires on the comsvcs dump; the deduped Sigma panel independently
corroborates it; that corroboration lands on the verdict's cross_check axis (``true``). The bare
structural detector carries no cross_check axis — enrichment is what adds the external witness. The
panel is one-sided: it can corroborate (TRUE) or stay silent (no axis), never contradict.
"""

from pathlib import Path

import pytest

from detection.cross_check import lsass_dump_corroborated, sigma_enrich
from detection.sigma_panel import SIGMA
from detection.subgraph import LSASS_DUMP, lsass_dump_verdicts, load_sysmon_events, match_pattern
from provenance import TRUE

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"

pytestmark = pytest.mark.skipif(
    not (OTRF.exists() and SIGMA.exists()), reason="OTRF corpus or SigmaHQ rules not present")


def test_enrich_witness_corroborates_the_comsvcs_dump():
    match = match_pattern(LSASS_DUMP, load_sysmon_events(str(OTRF)))[0]
    check, evidence = sigma_enrich("T1003.001", "process_access", leg="lsass_read")(match)
    assert check == TRUE                                   # ≥1 deduped class fires
    assert evidence["sigma_votes"] >= 1
    assert any("comsvcs" in n for n in evidence["sigma_rules"])


def test_enriched_verdict_carries_corroboration_on_cross_check():
    vs = lsass_dump_corroborated(str(OTRF))
    assert len(vs) == 1
    c = vs[0].to_contract()
    assert c["technique"] == "T1003.001"
    assert c["cross_check"] == "true"                      # external panel corroborates → cross_check axis


def test_bare_detector_has_no_cross_check_axis():
    # enrichment is what adds the witness; the structural detector alone makes no cross-paradigm claim
    c = lsass_dump_verdicts(str(OTRF))[0].to_contract()
    assert "cross_check" not in c
