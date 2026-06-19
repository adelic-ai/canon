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


def test_rust_and_python_rounds_agree():
    """Wiring check: firing the round through the Rust emitter gives the SAME verdicts as the Python path
    (Rust is proven faithful; rust-unsupported clauses fall back to eval_ir)."""
    from detection.rust_emitter import rust_available
    events = _events()[:2500]
    py = evaluate_round(events, ["T1003.001"], use_rust=False)
    rs = evaluate_round(events, ["T1003.001"], use_rust=True)
    assert py["engine"] == "python"
    if rust_available():
        assert rs["engine"] in ("rust", "rust+fallback")
    # identical verdicts regardless of engine — same rule, same hit counts, same order
    key = lambda r: [(v["rule"], v["n_hits"]) for v in r["verdicts"]]
    assert key(py) == key(rs)


def test_off_switch_native_vs_ocsf_and_the_calltrace_overmatch():
    """Step 5: the OTRF round runs native (switch OFF) or OCSF (switch ON, via the Sysmon adapter) — same
    engine, vocab per run. In OCSF mode the comsvcs rule loses CallTrace (no OCSF home) → it over-matches,
    and the verdict carries that as its rewrite warrant. This is the worked example of *when to leave OCSF off*."""
    from detection.ocsf_adapter import SYSMON_ADAPTER
    from detection.vocab import OCSF
    events = _events()[:2500]
    native = evaluate_round(events, ["T1003.001"], use_rust=False)
    ocsf = evaluate_round(events, ["T1003.001"], events_vocab=OCSF, rules_vocab=OCSF,
                          adapter=SYSMON_ADAPTER, use_rust=False)
    assert native["vocab"] == {"events": "native", "rules": "native"}
    assert ocsf["vocab"] == {"events": "ocsf", "rules": "ocsf"}
    # every OCSF verdict carries its rewrite warrant
    assert all("rewrite" in v for v in ocsf["verdicts"])
    # the sparse Sysmon adapter can't represent some selected rules at all in OCSF → honest NONEs (skipped,
    # not fired-on-everything). That non-zero count IS the "leave OCSF off" signal at the round level.
    assert ocsf["n_unevaluable"] > 0
    # CallTrace (no OCSF home) surfaces as a dropped field on a fired verdict (a process_access rule)
    assert any("CallTrace" in v["rewrite"]["dropped"] for v in ocsf["verdicts"])
    # the comsvcs rule fires in both; under OCSF it is flagged lossy (not faithful)
    nat_cs = [v for v in native["verdicts"] if "comsvcs" in v["rule"]]
    ocsf_cs = [v for v in ocsf["verdicts"] if "comsvcs" in v["rule"]]
    assert nat_cs and ocsf_cs
    assert any(not v["rewrite"]["faithful"] for v in ocsf_cs)
    # over-match: under OCSF the comsvcs rule fires on at least as many events as native (a field was dropped)
    assert max(v["n_hits"] for v in ocsf_cs) >= max(v["n_hits"] for v in nat_cs)
