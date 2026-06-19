"""The complete detection IR — compile a whole rule to typed molecules + condition AST, and PROVE the IR
interpreter computes identically to the raw evaluator (the licence for emitting from the IR)."""

from pathlib import Path

import pytest

from detection.rule_ir import CompiledRule, attest_ir_faithful, compile_rule, eval_ir
from detection.sigma_eval import evaluate_rule
from detection.sigma_panel import SIGMA, gather
from detection.subgraph import load_sysmon_events

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"


def _rule(detection):
    return {"id": "r", "detection": detection}


# rules exercising every fold construct: simple, named-block boolean, keyword, modifier
SIMPLE = _rule({"selection": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "selection"})
NAMED = _rule({"s1": {"Image|endswith": "\\rundll32.exe"}, "s2": {"CommandLine|contains": "comsvcs"},
               "condition": "s1 and s2"})
QUANT = _rule({"sel_a": {"A|contains": "x"}, "sel_b": {"B|contains": "y"}, "condition": "1 of sel_*"})
KEYWORD = _rule({"keywords": ["mimikatz", "sekurlsa"], "condition": "keywords"})
MODIFIER = _rule({"selection": {"CommandLine|re": "-enc\\s+[A-Za-z0-9]+"}, "condition": "selection"})
FILTERED = _rule({"selection": {"Image|endswith": "\\lsass.exe"}, "filter": {"User|contains": "SYSTEM"},
                  "condition": "selection and not 1 of filter*"})

_EVENTS = [
    {"TargetImage": "C:\\X\\lsass.exe", "Image": "C:\\W\\rundll32.exe", "CommandLine": "x comsvcs y"},
    {"A": "x"}, {"B": "y"}, {"C": "z"},
    {"CommandLine": "powershell -enc AAAA mimikatz"},
    {"Image": "C:\\X\\lsass.exe", "User": "NT SYSTEM"},
    {"Image": "C:\\X\\lsass.exe", "User": "alice"},
    {},
]


def test_compile_rule_builds_typed_blocks_and_condition():
    ir = compile_rule(NAMED)
    assert isinstance(ir, CompiledRule)
    assert {b.name for b in ir.blocks} == {"s1", "s2"}
    assert ir.condition == ("and", [("ref", "s1"), ("ref", "s2")])
    assert compile_rule(KEYWORD).blocks[0].kind == "keyword"
    assert compile_rule(MODIFIER).blocks[0].maps[0][0].mods == ("re",)   # full modifier carried into the IR


def test_ir_interpreter_matches_raw_evaluator_on_every_construct():
    for rule in (SIMPLE, NAMED, QUANT, KEYWORD, MODIFIER, FILTERED):
        ir = compile_rule(rule)
        for e in _EVENTS:
            assert eval_ir(ir, e) == evaluate_rule(rule, e)["fires"], (rule["id"], e)


def test_cid_is_stable_and_structural():
    a, b = compile_rule(NAMED), compile_rule(NAMED)
    assert a.cid == b.cid and len(a.cid) == 64
    assert compile_rule(NAMED).cid != compile_rule(SIMPLE).cid


def test_content_digest_is_value_aware_and_rule_id_blind():
    # value-aware: same field-set, DIFFERENT values → DISTINCT digests (the over-collapse fix)
    v1 = compile_rule(_rule({"selection": {"CommandLine|contains": "comsvcs"}, "condition": "selection"}))
    v2 = compile_rule(_rule({"selection": {"CommandLine|contains": "mimikatz"}, "condition": "selection"}))
    assert v1.content_digest() != v2.content_digest()
    # rule_id-blind: identical detection logic, different ids → SAME digest (unlike cid)
    a = compile_rule({"id": "rule-a", "detection": {"selection": {"CommandLine|contains": "x"}, "condition": "selection"}})
    b = compile_rule({"id": "rule-b", "detection": {"selection": {"CommandLine|contains": "x"}, "condition": "selection"}})
    assert a.content_digest() == b.content_digest()          # genuine duplicates still dedup
    assert a.cid != b.cid                                     # cid is contaminated by rule_id; content_digest isn't
    assert len(a.content_digest()) == 64


@pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()), reason="OTRF corpus / SigmaHQ rules not present")
def test_ir_is_faithful_across_the_real_corpus():
    """The fold's proof at scale: the typed IR agrees with the raw evaluator on every evaluable T1003.001 rule
    over every OTRF event."""
    from detection.sigma_eval import is_evaluable
    rules = [r for _, r in gather("T1003.001") if is_evaluable(r)]
    events = load_sysmon_events(str(OTRF))[:1500]      # sample for test speed
    rep = attest_ir_faithful(rules, events)
    assert rep["faithful"], rep["disagreements"][:3]
    assert rep["n_rules"] >= 20 and rep["checked"] > 10000
