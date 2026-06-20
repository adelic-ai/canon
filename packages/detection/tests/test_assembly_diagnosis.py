"""Assembly-level non-fire diagnosis — each fault class, on synthetic rules+events (no corpus needed)."""

from detection.assembly_diagnosis import (
    build_atom_reuse,
    diagnose_silent_rule,
)


def _rule(rid, detection):
    return {"id": rid, "tags": ["attack.t1003.001"], "detection": detection}


def test_wrong_channel_reads_none_of_the_events_fields():
    rule = _rule("r", {"sel": {"Image|endswith": "\\x.exe"}, "condition": "sel"})
    event = {"CommandLine": "whatever"}                     # no Image field at all
    d = diagnose_silent_rule(rule, event, {})
    assert d["fault"] == "wrong-channel" and not d["fires"]


def test_filter_excluded_positive_matches_but_a_filter_block_hits():
    rule = _rule("r", {"sel": {"A": "1"}, "filt": {"B": "2"}, "condition": "sel and not filt"})
    event = {"A": "1", "B": "2"}                            # sel matches, filter matches → excluded
    d = diagnose_silent_rule(rule, event, {})
    assert d["fault"] == "filter-excluded" and d["filters_hit"] == ["filt"]


def test_composition_gap_all_field_atoms_match_but_a_keyword_requirement_is_unmet():
    # field atoms all match in isolation, but the condition also needs a keyword block (not in the
    # field-atom decomposition) that the event doesn't satisfy → the fault is the assembly, not an atom.
    rule = _rule("r", {"sel": {"A": "1"}, "kw": ["needle"], "condition": "sel and kw"})
    event = {"A": "1"}                                      # no 'needle' anywhere
    d = diagnose_silent_rule(rule, event, {})
    assert d["fault"] == "composition-gap" and not d["fires"]
    assert d["exonerated"] and not d["value_miss"]         # the field atom is exonerated


def test_variant_miss_present_value_differs_but_the_atom_is_vouched_by_reuse():
    rule = _rule("r", {"sel": {"Image|endswith": "\\x.exe"}, "condition": "sel"})
    sibling = _rule("s", {"sel": {"Image|endswith": "\\x.exe"}, "condition": "sel"})   # shares the atom
    reuse = build_atom_reuse([rule, sibling])              # atom appears in 2 rules → vouched
    event = {"Image": "C:\\y.exe"}                          # Image present, value differs
    d = diagnose_silent_rule(rule, event, reuse)
    assert d["fault"] == "variant-miss"
    assert d["value_miss"] and not d["suspect_atoms"]      # a value-miss, but not a suspect (it's vouched)


def test_unvouched_miss_present_value_differs_and_the_atom_is_rule_unique():
    rule = _rule("r", {"sel": {"Image|endswith": "\\comsvc.exe"}, "condition": "sel"})  # likely a typo
    reuse = build_atom_reuse([rule])                       # atom only in this rule → reuse 1, unvouched
    event = {"Image": "C:\\windows\\system32\\comsvcs.exe"}  # present, value differs (missing 's')
    d = diagnose_silent_rule(rule, event, reuse)
    assert d["fault"] == "unvouched-miss"
    assert d["suspect_atoms"] and d["suspect_atoms"][0]["reuse"] == 1   # fingered as the bug locus


def test_fires_is_reported_when_the_rule_actually_matches():
    rule = _rule("r", {"sel": {"A": "1"}, "condition": "sel"})
    d = diagnose_silent_rule(rule, {"A": "1"}, {})
    assert d["fires"] and d["fault"] == "fires"
