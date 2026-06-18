"""Workspace parameters store + per-entity credibility baseline — the learned-parameters half of the
engine/workspace cut. Algorithm in canon (detection.baseline), learned values accumulating in the workspace.

The load-bearing claims: the parameter *grows* across runs (additive sufficient statistics), the credibility
estimate *sharpens* toward the entity's own mean as its data volume rises, and the engine carries no state —
everything that persists between runs goes through the workspace.
"""

import json

from detection.baseline import blend_baselines, credibility_estimates, learn_entity_baseline
from detection.workspace import (
    Ruleset,
    Source,
    Workspace,
    load_parameter,
    save_parameter,
    update_entity_baseline,
)


def _ws(tmp_path, events=None):
    from pathlib import Path
    base = Path(tmp_path)
    base.mkdir(parents=True, exist_ok=True)
    root = base / "ws"
    sources = ()
    if events is not None:
        ev = base / "events.json"
        ev.write_text(json.dumps(events))
        sources = (Source(ref=str(ev), kind="json"),)
    ws = Workspace(root=str(root), sources=sources, ruleset=Ruleset(corpus_ref="/n", version="-"))
    ws.save()
    return ws


def test_parameter_store_round_trips_and_is_none_when_absent(tmp_path):
    ws = _ws(tmp_path)
    assert load_parameter(ws, "entity_baseline") is None          # never learned → None, not a faked default
    save_parameter(ws, "entity_baseline", {"entities": {"A": {"n": 1, "sum": 2.0, "sumsq": 4.0}}, "K": 20.0})
    back = load_parameter(ws, "entity_baseline")
    assert back["entities"]["A"]["n"] == 1


def test_learn_and_blend_are_additive():
    e1 = [{"acct": "A", "bytes": 10}, {"acct": "A", "bytes": 20}, {"acct": "B", "bytes": 100}]
    b1 = learn_entity_baseline(e1, entity="acct", value="bytes")
    assert b1["entities"]["A"] == {"n": 2, "sum": 30.0, "sumsq": 500.0}
    e2 = [{"acct": "A", "bytes": 30}]
    b2 = learn_entity_baseline(e2, entity="acct", value="bytes")
    blended = blend_baselines(b1, b2)
    assert blended["entities"]["A"] == {"n": 3, "sum": 60.0, "sumsq": 1400.0}   # summed, not replaced
    assert blend_baselines(None, b2) == b2                                       # first run → observed


def test_credibility_sharpens_toward_own_mean_with_volume():
    # entity A's own mean is 10; population mean is pulled up by B. Estimate sits between, nearer pop when n
    # is small, nearer own as n grows — the Buhlmann property.
    small = {"entities": {"A": {"n": 2, "sum": 20.0, "sumsq": 200.0},
                          "B": {"n": 2, "sum": 200.0, "sumsq": 20000.0}}, "K": 20.0}
    big = {"entities": {"A": {"n": 200, "sum": 2000.0, "sumsq": 20000.0},
                        "B": {"n": 2, "sum": 200.0, "sumsq": 20000.0}}, "K": 20.0}
    a_small = credibility_estimates(small)["A"]
    a_big = credibility_estimates(big)["A"]
    assert a_small["own_mean"] == 10.0 and a_big["own_mean"] == 10.0
    assert a_big["Z"] > a_small["Z"]                              # more data → more credibility
    assert abs(a_big["estimate"] - 10.0) < abs(a_small["estimate"] - 10.0)   # sharpens toward own mean


def test_update_flow_grows_the_parameter_across_runs(tmp_path):
    # first run: learn from the workspace corpus, persist
    ws = _ws(tmp_path, events=[{"acct": "A", "bytes": 10}, {"acct": "A", "bytes": 12}, {"acct": "B", "bytes": 99}])
    r1 = update_entity_baseline(ws, entity="acct", value="bytes")
    assert r1["first_run"] is True
    assert load_parameter(ws, "entity_baseline") is not None      # the learned value lives in the workspace
    n_a_run1 = r1["baseline"]["entities"]["A"]["n"]
    z_a_run1 = r1["estimates"]["A"]["Z"]

    # second run over MORE data for A (same workspace): loads prior, blends, n + Z grow
    ev = json.loads((tmp_path / "events.json").read_text())
    ev += [{"acct": "A", "bytes": 11}] * 50
    (tmp_path / "events.json").write_text(json.dumps(ev))
    r2 = update_entity_baseline(ws, entity="acct", value="bytes")
    assert r2["first_run"] is False
    assert r2["baseline"]["entities"]["A"]["n"] > n_a_run1        # accumulated, not recomputed-from-scratch
    assert r2["estimates"]["A"]["Z"] > z_a_run1                   # credibility sharpened as it was re-run


def test_engine_carries_no_state_across_workspaces(tmp_path):
    wsa = _ws(tmp_path / "a", events=[{"acct": "A", "bytes": 5}])
    wsb = _ws(tmp_path / "b", events=[{"acct": "A", "bytes": 5000}])
    update_entity_baseline(wsa, entity="acct", value="bytes")
    update_entity_baseline(wsb, entity="acct", value="bytes")
    # each workspace holds its OWN baseline; the engine leaked nothing between them
    a = load_parameter(wsa, "entity_baseline")["entities"]["A"]
    b = load_parameter(wsb, "entity_baseline")["entities"]["A"]
    assert a["sum"] == 5.0 and b["sum"] == 5000.0
