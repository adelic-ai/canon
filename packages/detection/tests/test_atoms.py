"""Atom factoring — read the data once into the atom-truth artifact, fold rules over it (Phase B).

Pins: content-addressed atom ids dedup shared clauses (CSE); the factored path is faithful to per-rule
eval_ir; and the round's use_atoms engine gives identical verdicts."""

from pathlib import Path

import pytest

from detection.atoms import (
    atom_truth,
    attest_factored_agreement,
    clause_atom_id,
    collect_atoms,
    eval_rule_cached,
    fire_factored,
)
from detection.rule_ir import compile_rule, eval_ir
from detection.sigma_panel import SIGMA

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"


def _c(detection):
    return compile_rule({"id": "r", "detection": detection})


# two rules that SHARE a clause (Image endswith \rundll32.exe) but differ on the second
_R1 = _c({"selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "comsvcs"}, "condition": "selection"})
_R2 = _c({"selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "mimikatz"}, "condition": "selection"})
_EVENTS = [
    {"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32 comsvcs.dll dump"},
    {"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32 mimikatz"},
    {"Image": "C:\\notepad.exe", "CommandLine": "notepad"},
]


def test_atom_ids_dedup_shared_clauses():
    atoms = collect_atoms([_R1, _R2])
    # 3 distinct atoms (shared Image clause + two distinct CommandLine clauses), not 4 instances
    assert len(atoms) == 3
    # the shared Image clause has one id across both rules
    img1 = [c for b in _R1.blocks for m in b.maps for c in m if c.field == "Image"][0]
    img2 = [c for b in _R2.blocks for m in b.maps for c in m if c.field == "Image"][0]
    assert clause_atom_id(img1) == clause_atom_id(img2)


def test_atom_truth_is_per_atom_per_event():
    atoms = collect_atoms([_R1, _R2])
    truth = atom_truth(atoms, _EVENTS)
    assert all(len(col) == len(_EVENTS) for col in truth.values())
    # the shared rundll32 atom is true on the first two events, false on the third
    img = [c for b in _R1.blocks for m in b.maps for c in m if c.field == "Image"][0]
    assert truth[clause_atom_id(img)] == [True, True, False]


def test_factored_hits_equal_per_rule_eval_ir():
    res = fire_factored([_R1, _R2], _EVENTS)
    naive = [sum(1 for e in _EVENTS if eval_ir(ir, e)) for ir in (_R1, _R2)]
    assert res["hits"] == naive == [1, 1]                 # R1 catches event 0, R2 catches event 1
    # dedup: 3 distinct atoms vs 4 clause instances
    assert res["n_atoms"] == 3 and res["n_instances"] == 4 and res["dedup_factor"] > 1.0


def test_factored_agreement_gate_is_faithful():
    res = attest_factored_agreement([_R1, _R2], _EVENTS)
    assert res["faithful"] and res["disagreements"] == [] and res["checked"] == 6


def test_eval_rule_cached_matches_eval_ir_pointwise():
    atoms = collect_atoms([_R1, _R2])
    truth = atom_truth(atoms, _EVENTS)
    for ir in (_R1, _R2):
        for j, e in enumerate(_EVENTS):
            assert eval_rule_cached(ir, j, truth) == eval_ir(ir, e)


@pytest.mark.skipif(not (OTRF.exists() and SIGMA.exists()),
                    reason="OTRF corpus / SigmaHQ rules not present")
def test_round_atoms_engine_agrees_and_dedups_on_otrf():
    """The round's use_atoms engine gives identical verdicts to the Python path, and the selected
    rules share atoms (dedup_factor > 1)."""
    from detection.round import evaluate_round, select_detections, environment_profile
    from detection.subgraph import load_sysmon_events
    events = load_sysmon_events(str(OTRF))[:2500]
    py = evaluate_round(events, ["T1003.001"], use_rust=False)
    at = evaluate_round(events, ["T1003.001"], use_rust=False, use_atoms=True)
    assert at["engine"] == "atoms"
    key = lambda r: [(v["rule"], v["n_hits"]) for v in r["verdicts"]]
    assert key(py) == key(at)                              # identical verdicts
    # the selected rules genuinely share atoms
    prof = environment_profile(events)
    compiled = [compile_rule(s["rule"]) for s in select_detections(prof, ["T1003.001"])]
    res = fire_factored(compiled, events[:200])
    assert res["dedup_factor"] > 1.0
