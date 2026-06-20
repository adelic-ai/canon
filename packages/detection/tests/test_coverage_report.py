"""Stage 5 — per-TTP structural coverage: the layer counts, the honest NONE gap, the dedup of concepts.

(Complements ``test_coverage.py``, which tests the event-side *corroboration* coverage in ``sigma_panel``;
this is the corpus-side *structural* layer report wired into the treatment manifest.)
"""

from detection.coverage import coverage_report
from detection.rule_ir import compile_rule
from detection.rule_lattice import build_lattice


def _mk(rid, tech, det):
    return {"id": rid, "tags": [f"attack.{tech.lower()}"], "detection": det}


def _cov(rules, techniques):
    compiled = [compile_rule(r) for r in rules]
    return coverage_report(rules, compiled, build_lattice(compiled), techniques)


def test_layers_and_subsumption_family_within_a_technique():
    rules = [
        _mk("r1", "T1003.001", {"selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "selection"}),
        _mk("r2", "T1003.001", {"selection": {"Image|endswith": "\\rundll32.exe",
                                              "CommandLine|contains": "comsvcs"}, "condition": "selection"}),
        _mk("r3", "T1059.001", {"selection": {"CommandLine|contains": "powershell"}, "condition": "selection"}),
    ]
    cov = _cov(rules, ["T1003.001", "T1059.001"])
    assert cov["covered"] == ["T1003.001", "T1059.001"]
    t = cov["per_technique"]["T1003.001"]
    assert t["rules"] == 2
    assert t["atoms"] >= 2                            # rundll32 + comsvcs clauses
    assert "endswith" in t["primitives"]
    assert t["families"] >= 1                         # r1 (general) ⊃ r2 (stricter)


def test_gap_is_none_not_zero_coverage():
    rules = [_mk("r1", "T1003.001", {"selection": {"Image|endswith": "\\x.exe"}, "condition": "selection"})]
    cov = _cov(rules, ["T1003.001", "T1547.001"])
    assert cov["covered"] == ["T1003.001"]
    assert cov["gaps"] == ["T1547.001"]              # no rule tags it → NONE, not a 0%-covered assertion
    assert "T1547.001" not in cov["per_technique"]   # absence is not a record of zero


def test_concepts_collapse_identical_rules_structurally():
    det = {"selection": {"Image|endswith": "\\x.exe"}, "condition": "selection"}
    rules = [_mk("a", "T1003.001", det), _mk("b", "T1003.001", dict(det))]
    t = _cov(rules, ["T1003.001"])["per_technique"]["T1003.001"]
    assert t["rules"] == 2 and t["concepts"] == 1    # exactMatch dedup → one structural concept
    assert t["redundancy_ratio"] == 2.0              # STRUCTURAL ratio — behavioral meaning awaits catch-set
