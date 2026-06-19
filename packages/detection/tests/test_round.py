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
    # whittled below the full set claiming T1003.001 (applicable-only + true content-duplicates collapsed),
    # but content-aware: value-distinct detections are KEPT, not over-collapsed.
    rules = sel
    assert 0 < len(rules) < 79
    # only applicable detections selected — every chosen rule's required fields are in the profile
    from detection.rule_ir import compile_rule
    from detection.round import _required_fields
    present = set(prof["fields"])
    assert all(_required_fields(compile_rule(s["rule"])) <= present for s in sel)


def test_content_key_recovers_detections_the_field_set_key_dropped():
    """The recall fix: the value-aware concept key keeps value-distinct detections that the old field-set
    key collapsed into one (and thus silently dropped at best-peer selection). So content-aware selection
    yields strictly MORE detections than a field-set re-grouping of the same selected rules."""
    from detection.rule_ir import compile_rule
    from detection.sigma_panel import signature
    prof = environment_profile(_events())
    sel = select_detections(prof, ["T1003.001"])                  # content-aware (the round's key)
    field_set_concepts = {signature(s["rule"]) for s in sel}      # how many the field-set key would keep
    # content-aware kept more distinct detections than the field-set key would — recovered, not dropped
    assert len(sel) > len(field_set_concepts)


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


def test_off_switch_native_vs_ocsf_carries_no_home_fields():
    """Step 5 + the OCSF lift: the OTRF round runs native (switch OFF) or OCSF (switch ON) — same engine,
    vocab per run. The no-core-home fields (CallTrace/GrantedAccess/OriginalFileName) are carried in OCSF's
    `unmapped` rather than dropped, so the comsvcs rule fires FAITHFULLY under OCSF — no over-match."""
    from detection.ocsf_adapter import SYSMON_ADAPTER
    from detection.vocab import OCSF
    events = _events()[:2500]
    native = evaluate_round(events, ["T1003.001"], use_rust=False)
    ocsf = evaluate_round(events, ["T1003.001"], events_vocab=OCSF, rules_vocab=OCSF,
                          adapter=SYSMON_ADAPTER, use_rust=False)
    assert native["vocab"] == {"events": "native", "rules": "native"}
    assert ocsf["vocab"] == {"events": "ocsf", "rules": "ocsf"}
    assert all("rewrite" in v for v in ocsf["verdicts"])
    # other-logsource rules (registry/file/image_load) have NO Sysmon-process mappings → still unevaluable,
    # skipped as honest NONEs (not fired-on-everything).
    assert ocsf["n_unevaluable"] > 0
    # CallTrace is now CARRIED (in unmapped), not dropped — no fired verdict reports it dropped
    assert not any("CallTrace" in v["rewrite"]["dropped"] for v in ocsf["verdicts"])
    # the comsvcs rule fires in both and is FAITHFUL under OCSF (nothing dropped) — no over-match
    nat_cs = [v for v in native["verdicts"] if "comsvcs" in v["rule"]]
    ocsf_cs = [v for v in ocsf["verdicts"] if "comsvcs" in v["rule"]]
    assert nat_cs and ocsf_cs
    assert all(v["rewrite"]["faithful"] for v in ocsf_cs)
    # no over-match: under OCSF the comsvcs rule fires on the SAME events as native (carried CallTrace)
    assert max(v["n_hits"] for v in ocsf_cs) == max(v["n_hits"] for v in nat_cs)
