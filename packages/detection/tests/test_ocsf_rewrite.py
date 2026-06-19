"""Sigma→OCSF rule rewrite (step 3 of the OFF-able normalization waist).

Pins: the rewrite remaps clause fields onto OCSF paths (structure/mods/values/condition
preserved); a faithful rewrite fires identically on OCSF events as the native rule on native
events; a field with no OCSF home is dropped + reported, and the lossy rule then over-matches
(the divergence the step-4 gate explains)."""

from pathlib import Path

import pytest

from detection.ocsf_adapter import SYSMON_ADAPTER
from detection.ocsf_rewrite import attest_ocsf_agreement, rewrite_rule_to_ocsf
from detection.rule_ir import compile_rule, eval_ir
from detection.sigma_eval import is_evaluable
from detection.sigma_panel import SIGMA, gather
from detection.vocab import OCSF, coheres

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"


def _compile(detection: dict):
    return compile_rule({"id": "test-rule", "detection": detection})


# ── a clean process_creation rule: all fields have exact OCSF homes ───────────────────────
_PROC_CREATE = {
    "selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "comsvcs.dll"},
    "condition": "selection",
}

# ── the canonical comsvcs process_access rule: CallTrace has NO OCSF home ──────────────────
_COMSVCS = {
    "selection": {"TargetImage|endswith": "\\lsass.exe",
                  "SourceImage|endswith": "\\rundll32.exe",
                  "CallTrace|contains": "comsvcs.dll"},
    "condition": "selection",
}


def test_rewrite_remaps_fields_to_ocsf_paths_preserving_mods_and_values():
    rw = rewrite_rule_to_ocsf(_compile(_PROC_CREATE), SYSMON_ADAPTER)
    clauses = [c for b in rw.rule.blocks for m in b.maps for c in m]
    by_field = {c.field: c for c in clauses}
    # fields are now OCSF paths
    assert "process.file.path" in by_field and "process.cmd_line" in by_field
    assert "Image" not in by_field and "CommandLine" not in by_field
    # modifiers and values are carried verbatim — only the field name changed
    assert by_field["process.file.path"].mods == ("endswith",)
    assert by_field["process.file.path"].values == ("\\rundll32.exe",)
    # condition AST untouched
    assert rw.rule.condition == _compile(_PROC_CREATE).condition


def test_faithful_rewrite_fires_identically_on_ocsf_events():
    native_rule = _compile(_PROC_CREATE)
    rw = rewrite_rule_to_ocsf(native_rule, SYSMON_ADAPTER)
    assert rw.faithful and rw.grade == "exact" and rw.dropped == ()
    # a hit: native rule on native event == rewritten rule on the normalized event
    hit = {"Image": "C:\\Windows\\System32\\rundll32.exe",
           "CommandLine": "rundll32.exe comsvcs.dll, MiniDump 624 dump"}
    miss = {"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe"}
    for ev in (hit, miss):
        ocsf_ev = SYSMON_ADAPTER.normalize(ev)
        assert eval_ir(rw.rule, ocsf_ev) == eval_ir(native_rule, ev)
    # and it did actually fire on the hit (not vacuously equal on two misses)
    assert eval_ir(rw.rule, SYSMON_ADAPTER.normalize(hit)) is True


def test_no_core_home_field_is_carried_in_unmapped_not_dropped():
    from detection.ocsf_adapter import CARRIED
    rw = rewrite_rule_to_ocsf(_compile(_COMSVCS), SYSMON_ADAPTER)
    # CallTrace has no CORE OCSF home → carried verbatim in unmapped (NOT dropped, NOT silent)
    assert rw.dropped == ()
    assert rw.faithful                       # nothing dropped → the rule still fires correctly
    # the CallTrace clause now reads unmapped.CallTrace; the mappable fields crossed too
    fields = {c.field for b in rw.rule.blocks for m in b.maps for c in m}
    assert "unmapped.CallTrace" in fields
    assert "process.file.path" in fields and "actor.process.file.path" in fields
    # CallTrace is graded `carried` — match-faithful, not cross-source-normalized; it's the rule's worst edge
    assert SYSMON_ADAPTER.why("CallTrace").grade == CARRIED
    assert rw.grade == CARRIED


def test_carried_field_eliminates_the_over_match():
    """The fix: native comsvcs requires CallTrace contains comsvcs.dll; carrying CallTrace in unmapped
    lets the OCSF-rewritten rule read it too, so it fires on exactly the same events — no over-match."""
    native_rule = _compile(_COMSVCS)
    rw = rewrite_rule_to_ocsf(native_rule, SYSMON_ADAPTER)
    # a rundll32→lsass access WITHOUT comsvcs.dll in the call stack (benign-shaped)
    benign = {"TargetImage": "C:\\Windows\\System32\\lsass.exe",
              "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
              "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x9c5b4|C:\\Windows\\System32\\KERNELBASE.dll"}
    hit = {**benign, "CallTrace": "ntdll.dll|C:\\Windows\\system32\\comsvcs.dll+0x1234"}
    # native and OCSF agree on BOTH — carried CallTrace means no over-match
    assert eval_ir(native_rule, benign) is False
    assert eval_ir(rw.rule, SYSMON_ADAPTER.normalize(benign)) is False     # was True (over-match) before the carry
    assert eval_ir(native_rule, hit) is True
    assert eval_ir(rw.rule, SYSMON_ADAPTER.normalize(hit)) is True


def test_rule_grade_is_worst_field():
    # a rule keyed on User (broad) takes the worst grade across its fields
    rule = _compile({"selection": {"Image|endswith": "\\x.exe", "User|contains": "admin"},
                     "condition": "selection"})
    rw = rewrite_rule_to_ocsf(rule, SYSMON_ADAPTER)
    assert rw.faithful                       # both fields have homes
    assert rw.grade == "broad"               # Image exact, User broad → worst wins


def test_rewritten_rules_cohere_with_ocsf_events():
    # both sides on the OCSF vocabulary → the round can fire a coherent pair
    assert coheres(SYSMON_ADAPTER.vocabulary(), OCSF)


# ── step 4: the native-as-oracle faithfulness gate ───────────────────────────────────────
_RULE_DICTS = [{"id": "proc-create", "detection": _PROC_CREATE},
               {"id": "comsvcs", "detection": _COMSVCS}]


def test_faithful_exact_rule_never_diverges_the_theorem():
    # the gate's strongest claim: a faithful all-exact rewrite agrees on every event
    events = [{"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32 comsvcs.dll MiniDump"},
              {"Image": "C:\\notepad.exe", "CommandLine": "notepad"},
              {"Image": "C:\\rundll32.exe", "CommandLine": "rundll32 shell32.dll"}]
    res = attest_ocsf_agreement([{"id": "proc-create", "detection": _PROC_CREATE}], events, SYSMON_ADAPTER)
    assert res["attested"]
    assert res["unexplained_divergences"] == [] and res["explained_divergences"] == []
    assert res["agreements"] == res["checked"] == 3
    assert res["per_rule"][0] == {"rule": "proc-create", "grade": "exact", "dropped": [],
                                  "faithful": True, "n_diverge": 0}


def test_gate_has_no_divergence_when_the_no_home_field_is_carried():
    # a benign rundll32→lsass access (no comsvcs.dll). Before the carry, the OCSF rule over-matched
    # (an explained divergence). Now CallTrace rides in unmapped → the rule reads it → NO divergence.
    events = [{"TargetImage": "C:\\Windows\\System32\\lsass.exe",
               "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
               "CallTrace": "ntdll.dll|KERNELBASE.dll"}]
    res = attest_ocsf_agreement([{"id": "comsvcs", "detection": _COMSVCS}], events, SYSMON_ADAPTER)
    assert res["attested"]
    assert res["explained_divergences"] == [] and res["unexplained_divergences"] == []
    # the comsvcs rule is faithful — CallTrace carried, nothing dropped
    assert res["per_rule"][0]["faithful"] and res["per_rule"][0]["dropped"] == []


def test_gate_runs_both_rules_and_reports_per_rule():
    events = [{"Image": "C:\\rundll32.exe", "CommandLine": "rundll32 comsvcs.dll MiniDump"},
              {"TargetImage": "C:\\lsass.exe", "SourceImage": "C:\\rundll32.exe", "CallTrace": "ntdll.dll"}]
    res = attest_ocsf_agreement(_RULE_DICTS, events, SYSMON_ADAPTER)
    assert res["attested"] and res["n_rules"] == 2 and res["checked"] == 4
    by_rule = {r["rule"]: r for r in res["per_rule"]}
    assert by_rule["proc-create"]["faithful"] and by_rule["proc-create"]["grade"] == "exact"
    # comsvcs is now faithful too — CallTrace carried in unmapped, nothing dropped; its grade is `carried`
    assert by_rule["comsvcs"]["faithful"] and by_rule["comsvcs"]["dropped"] == []
    assert by_rule["comsvcs"]["grade"] == "carried"


@pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()),
                    reason="OTRF corpus / SigmaHQ rules not present")
def test_attest_on_real_otrf_corpus():
    """The acceptance test: fire the T1003.001 Sysmon rules native vs OCSF over real OTRF
    events. Attested = no unexplained divergence; the comsvcs over-match is explained."""
    from detection.subgraph import load_sysmon_events
    events = load_sysmon_events(str(OTRF))[:2000]
    rules = []
    for _p, r in gather("T1003.001", root=SIGMA):
        ls = r.get("logsource", {})
        if ls.get("product") == "windows" and ls.get("category") in ("process_creation", "process_access") \
                and is_evaluable(r):
            rules.append(r)
    assert rules, "expected some Sysmon process rules for T1003.001"
    res = attest_ocsf_agreement(rules, events, SYSMON_ADAPTER)
    assert res["attested"], res["unexplained_divergences"][:5]
