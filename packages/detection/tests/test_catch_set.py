"""Catch-set grounding (stage 4) — behavioral synonymy and its comparison to the structural lattice.

Two layers: deterministic unit tests over tiny hand-built rules+events (no corpus needed, CI-safe) that pin
the grouping + the structural-vs-catch cross-tab including the load-bearing off-diagonal (co-catch with NO
structural edge); and a skip-if-absent integration test pinning the real n=1 OTRF T1003.001 result.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detection.catch_set import group_by_catch_set, ground_lattice, rule_catch_sets


def _rule(rid: str, field_mod: str, value: str) -> dict:
    """A minimal evaluable single-selection Sigma rule on one (field|mod == value) clause."""
    return {"id": rid,
            "detection": {"selection": {field_mod: value}, "condition": "selection"},
            "logsource": {"category": "process_creation", "product": "windows"}}


# ── two events to catch ────────────────────────────────────────────────────────────────────────
FOO = {"Image": "c:\\foo.exe", "CommandLine": "do evil things"}
BAR = {"Image": "c:\\bar.exe", "CommandLine": "benign"}


def test_rule_catch_sets_records_caught_on():
    a = _rule("a", "Image|endswith", "\\foo.exe")    # catches FOO only
    c = _rule("c", "Image|endswith", "\\bar.exe")    # catches BAR only
    d = _rule("d", "Image|endswith", "\\nope.exe")   # catches neither
    catch = rule_catch_sets([("a", a), ("c", c), ("d", d)], [FOO, BAR])
    assert len(catch["a"]) == 1 and len(catch["c"]) == 1
    assert catch["d"] == frozenset()                  # silent — empty catch-set, not absent from the map
    assert catch["a"] != catch["c"]                   # different instance → different catch-set


def test_group_by_catch_set_classes_and_silent():
    a = _rule("a", "Image|endswith", "\\foo.exe")
    b = _rule("b", "Image|endswith", "\\foo.exe")     # identical logic, different id → catch-set synonym of a
    c = _rule("c", "Image|endswith", "\\bar.exe")
    d = _rule("d", "Image|endswith", "\\nope.exe")    # silent
    g = group_by_catch_set([("a", a), ("b", b), ("c", c), ("d", d)], [FOO, BAR])
    assert g["n_instances"] == 2 and g["n_rules"] == 4
    assert g["silent"] == ["d"]                        # empty catch-set → silent, NOT a synonymy class
    classes = {tuple(c["rules"]) for c in g["catch_classes"]}
    assert ("a", "b") in classes                       # a,b co-catch FOO → one behavioral class
    assert ("c",) in classes                           # c alone catches BAR
    assert g["cid"]                                     # reproducible content address


def test_ground_lattice_exact_agrees_and_disjoint_has_no_edge():
    a = _rule("a", "Image|endswith", "\\foo.exe")
    b = _rule("b", "Image|endswith", "\\foo.exe")     # structurally exact + co-catch
    c = _rule("c", "Image|endswith", "\\bar.exe")     # disjoint clause-set + disjoint catch-set
    gr = ground_lattice([("a", a), ("b", b), ("c", c)], [FOO, BAR])
    assert gr["n_catchers"] == 3
    # a,b: co-catch ↔ structurally exact  (diagonal agreement)
    assert gr["crosstab"]["co-catch"] == {"exact": 1}
    # a,c and b,c: disjoint behavior ↔ no structural edge (disjoint clause-sets)
    assert gr["crosstab"]["disjoint"] == {"none": 2}
    assert gr["headline"]["co_catch_pairs"] == 1
    assert gr["headline"]["missed_by_structure"] == []


def test_ground_lattice_surfaces_synonymy_the_structure_misses():
    """The load-bearing off-diagonal: two rules that catch the SAME instance via DISJOINT discriminators
    (one on Image, one on CommandLine) co-catch behaviorally but have NO structural edge — exactly the
    behavioral synonymy a structure-only lattice cannot see. `missed_by_structure` must surface it."""
    e = _rule("e", "Image|endswith", "\\foo.exe")        # catches FOO via Image
    f = _rule("f", "CommandLine|contains", "evil")       # catches FOO via CommandLine — disjoint clauses
    gr = ground_lattice([("e", e), ("f", f)], [FOO])
    assert gr["n_catchers"] == 2
    assert gr["crosstab"] == {"co-catch": {"none": 1}}   # co-catch, but structurally unrelated
    assert gr["headline"]["co_catch_pairs"] == 1
    assert gr["headline"]["with_structural_edge"] == 0
    assert gr["headline"]["missed_by_structure"] == [("e", "f")]


# ── real n=1 grounding: skip-if-absent (engine/workspace boundary — data is path-ref'd, never committed) ──
_OTRF = Path("/Users/shunhonda/data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json")
_SIGMA = Path("/Users/shunhonda/canon/packages/semantic-cyber/data/sigma-rules")


@pytest.mark.skipif(not (_OTRF.exists() and _SIGMA.exists()),
                    reason="OTRF corpus or Sigma ruleset absent (path-ref'd workspace data)")
def test_otrf_n1_grounding_two_catchers_related_not_exact():
    from detection.catch_set import otrf_lsass_t1003_grounding
    r = otrf_lsass_t1003_grounding(str(_OTRF), sigma_root=_SIGMA)
    g, gr = r["grouping"], r["grounding"]
    assert g["n_instances"] == 1 and g["n_rules"] == 79
    assert gr["n_catchers"] == 2                          # the 2 catchers (matches the fidelity scorecard)
    assert len(g["silent"]) == 77
    # the 2 co-catch, and the lattice connects them as `related` (overlap) — NOT `exact`: dedup alone would
    # have missed this behavioral synonymy, so the graded edges are load-bearing.
    assert gr["crosstab"] == {"co-catch": {"related": 1}}
    assert gr["headline"]["missed_by_structure"] == []
