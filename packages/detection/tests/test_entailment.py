"""Phase-B entailment — model-checking over the artifact: pruning, short-circuit, faithfulness."""

from pathlib import Path

import pytest

from detection.entailment import (
    attest_entailment_agreement,
    check_entailment,
    eval_ordered,
    has_negation,
    selectivity,
)
from detection.atoms import atom_truth, collect_atoms
from detection.rule_ir import compile_rule, eval_ir
from detection.sigma_panel import SIGMA

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"


def _c(detection):
    return compile_rule({"id": "r", "detection": detection})


_POS = _c({"selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "comsvcs"},
           "condition": "selection"})
_NEG = _c({"selection": {"Image|endswith": "\\lsass.exe"}, "filter": {"User|contains": "SYSTEM"},
           "condition": "selection and not filter"})
_PURE_NEG = _c({"selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "not selection"})

_EVENTS = [
    {"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32 comsvcs.dll dump"},  # _POS fires
    {"Image": "C:\\Windows\\System32\\lsass.exe", "User": "alice"},          # _NEG fires (lsass, not SYSTEM)
    {"Image": "C:\\Windows\\System32\\lsass.exe", "User": "NT SYSTEM"},      # _NEG excluded
    {"Other": "z"},                                                          # only _PURE_NEG fires (no atom true)
]


def test_has_negation_detects_not_anywhere():
    assert not has_negation(_POS.condition)
    assert has_negation(_NEG.condition) and has_negation(_PURE_NEG.condition)


def test_check_entailment_hits_equal_eval_ir():
    res = check_entailment([_POS, _NEG, _PURE_NEG], _EVENTS)
    naive = [sum(1 for e in _EVENTS if eval_ir(ir, e)) for ir in (_POS, _NEG, _PURE_NEG)]
    assert res["hits"] == naive


def test_prune_skips_positive_rule_on_atomless_events_but_not_negated_ones():
    res = check_entailment([_POS, _NEG, _PURE_NEG], _EVENTS)
    # the positive rule is pruned on events where none of its atoms are true → real work avoided
    assert res["pairs_pruned"] > 0 and 0.0 < res["prune_ratio"] <= 1.0


def test_negated_rule_fires_on_an_event_with_no_true_atom():
    # _PURE_NEG ("not selection") MUST fire on the atomless event — proves the prune is NOT applied to it
    res = check_entailment([_PURE_NEG], _EVENTS)
    assert res["hits"][0] == sum(1 for e in _EVENTS if eval_ir(_PURE_NEG, e))
    assert res["hits"][0] >= 1                              # fires on {"Other": "z"} (and others)
    # and the engine evaluated it on every event (no prune for negated rules)
    assert res["pairs_pruned"] == 0


def test_eval_ordered_is_faithful_pointwise():
    atoms = collect_atoms([_POS, _NEG, _PURE_NEG])
    truth = atom_truth(atoms, _EVENTS)
    sel = selectivity(truth)
    for ir in (_POS, _NEG, _PURE_NEG):
        for j, e in enumerate(_EVENTS):
            assert eval_ordered(ir, j, truth, sel) == eval_ir(ir, e)


def test_entailment_agreement_gate_is_faithful():
    res = attest_entailment_agreement([_POS, _NEG, _PURE_NEG], _EVENTS)
    assert res["faithful"] and res["checked"] == 12


@pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()),
                    reason="OTRF corpus / SigmaHQ rules not present")
def test_entailment_faithful_and_prunes_hard_on_otrf():
    """On the real round's selected rules over OTRF: identical hits to eval_ir, and the prune skips the
    large majority of (rule, event) pairs (most rules don't touch most events)."""
    from detection.round import environment_profile, select_detections
    from detection.subgraph import load_sysmon_events
    events = load_sysmon_events(str(OTRF))[:2000]
    compiled = [compile_rule(s["rule"]) for s in select_detections(environment_profile(events), ["T1003.001"])]
    res = check_entailment(compiled, events)
    naive = [sum(1 for e in events if eval_ir(ir, e)) for ir in compiled]
    assert res["hits"] == naive                            # faithful on real data
    assert res["prune_ratio"] > 0.5                        # the majority of pairs pruned
    att = attest_entailment_agreement(compiled, events[:300])
    assert att["faithful"]


@pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()),
                    reason="OTRF corpus / SigmaHQ rules not present")
def test_round_entailment_engine_agrees_with_python_on_otrf():
    """The round's use_entailment engine (Mode B wired live) gives identical verdicts to the Python
    path — the pruned Phase-B reasoner is now a real, faithful firing engine in evaluate_round."""
    from detection.round import evaluate_round
    from detection.subgraph import load_sysmon_events
    events = load_sysmon_events(str(OTRF))[:2500]
    py = evaluate_round(events, ["T1003.001"], use_rust=False)
    ent = evaluate_round(events, ["T1003.001"], use_rust=False, use_entailment=True)
    assert ent["engine"] == "entailment"
    key = lambda r: [(v["rule"], v["n_hits"]) for v in r["verdicts"]]
    assert key(py) == key(ent)                             # identical verdicts, faithful
