"""Detection round — profile → select (applicable, best-peer) → fire → locate → rank, over a log."""

from pathlib import Path

import pytest

from detection.round import environment_profile, evaluate_round, select_detections
from detection.sigma_panel import SIGMA

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
pytestmark = pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()),
                                reason="OTRF corpus / SigmaHQ rules not present")


def _events():
    from detection.subgraph import load_sysmon_events
    return load_sysmon_events(str(OTRF))


def test_profile_infers_the_telemetry_surface():
    prof = environment_profile(_events())
    assert prof["n_events"] > 100
    assert "TargetImage" in prof["fields"] and "CallTrace" in prof["fields"]   # process_access fields present


def test_select_whittles_to_applicable_best_peers():
    prof = environment_profile(_events())
    sel = select_detections(prof, ["T1003.001"])
    # whittled: far fewer than the ~79 rules claiming T1003.001 (FCA concepts, applicable-only, best-peer)
    rules = sel
    assert 0 < len(rules) < 40
    # only applicable detections selected — every chosen rule's required fields are in the profile
    from detection.rule_ir import compile_rule
    from detection.round import _required_fields
    present = set(prof["fields"])
    assert all(_required_fields(compile_rule(s["rule"])) <= present for s in sel)


def test_round_fires_and_ranks():
    rnd = evaluate_round(_events()[:2500], ["T1003.001"])      # sample for test speed (full run is ~42k events)
    assert rnd["n_selected"] >= 1 and rnd["n_fired"] >= 1
    # the comsvcs detection fired and is located in the kill chain
    fired = rnd["verdicts"]
    assert any(v["tactic"] == "credential-access" and v["severity"] == "high" for v in fired)
    assert any("comsvcs" in v["rule"] for v in fired)
    # ranked: severities are non-increasing
    ranks = [{"high": 3, "medium": 2, "low": 1}[v["severity"]] for v in fired]
    assert ranks == sorted(ranks, reverse=True)
