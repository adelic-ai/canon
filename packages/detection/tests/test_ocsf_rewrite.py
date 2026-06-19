"""Sigma→OCSF rule rewrite (step 3 of the OFF-able normalization waist).

Pins: the rewrite remaps clause fields onto OCSF paths (structure/mods/values/condition
preserved); a faithful rewrite fires identically on OCSF events as the native rule on native
events; a field with no OCSF home is dropped + reported, and the lossy rule then over-matches
(the divergence the step-4 gate explains)."""

from detection.ocsf_adapter import SYSMON_ADAPTER
from detection.ocsf_rewrite import rewrite_rule_to_ocsf
from detection.rule_ir import compile_rule, eval_ir
from detection.vocab import OCSF, coheres


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


def test_no_ocsf_home_field_is_dropped_and_reported_not_silent():
    rw = rewrite_rule_to_ocsf(_compile(_COMSVCS), SYSMON_ADAPTER)
    # CallTrace has no OCSF home → dropped + reported, rule flagged unfaithful
    assert rw.dropped == ("CallTrace",)
    assert not rw.faithful and rw.grade == "unfaithful"
    # the mappable fields still crossed (exact)
    mapped_fields = {nf for nf, _, _ in rw.mapped}
    assert mapped_fields == {"TargetImage", "SourceImage"}
    assert all(g == "exact" for _, _, g in rw.mapped)
    # the rewritten rule no longer references CallTrace
    fields = {c.field for b in rw.rule.blocks for m in b.maps for c in m}
    assert "process.file.path" in fields and "actor.process.file.path" in fields
    assert not any("CallTrace" in f for f in fields)


def test_dropping_the_load_bearing_field_makes_the_rule_over_match():
    """The honest consequence of the loss: native comsvcs requires CallTrace contains
    comsvcs.dll; the OCSF-rewritten rule lost CallTrace, so it fires on ANY rundll32→lsass
    access — a divergence (over-match), surfaced, that the step-4 faithfulness gate enumerates."""
    native_rule = _compile(_COMSVCS)
    rw = rewrite_rule_to_ocsf(native_rule, SYSMON_ADAPTER)
    # a rundll32→lsass access WITHOUT comsvcs.dll in the call stack (benign-shaped)
    ev = {"TargetImage": "C:\\Windows\\System32\\lsass.exe",
          "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
          "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x9c5b4|C:\\Windows\\System32\\KERNELBASE.dll"}
    # native rule: does NOT fire (CallTrace lacks comsvcs.dll)
    assert eval_ir(native_rule, ev) is False
    # OCSF-rewritten rule: DOES fire (CallTrace clause was dropped) → over-match
    assert eval_ir(rw.rule, SYSMON_ADAPTER.normalize(ev)) is True


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
