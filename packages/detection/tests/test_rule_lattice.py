"""The SKOS-graded rule-relation lattice (stage 3) — graded edges, dedup as the exactMatch slice."""

from pathlib import Path

import pytest

from detection.rule_ir import compile_rule
from detection.rule_lattice import (
    build_lattice,
    clause_set,
    exact_classes,
    relation,
    why,
)
from detection.sigma_panel import SIGMA


def _c(detection):
    return compile_rule({"id": detection.get("_id", "r"), "detection":
                         {k: v for k, v in detection.items() if k != "_id"}})


# a broad base, a stricter (narrower) child, a synonym, an overlap, a disjoint
_BASE = _c({"_id": "base", "selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "selection"})
_STRICT = _c({"_id": "strict", "selection": {"Image|endswith": "\\rundll32.exe",
                                             "CommandLine|contains": "comsvcs"}, "condition": "selection"})
_SYNONYM = _c({"_id": "syn", "selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "selection"})
_OVERLAP = _c({"_id": "ov", "selection": {"CommandLine|contains": "comsvcs",
                                          "User|contains": "admin"}, "condition": "selection"})
_DISJOINT = _c({"_id": "dis", "selection": {"TargetObject|contains": "\\Run\\"}, "condition": "selection"})


def test_relation_is_extensional_more_clauses_is_narrower():
    base, strict = clause_set(_BASE), clause_set(_STRICT)
    assert relation(strict, base) == "narrower"      # strict has more clauses → matches a subset
    assert relation(base, strict) == "broader"       # base is more general
    assert relation(_BASE and clause_set(_BASE), clause_set(_SYNONYM)) == "exact"
    assert relation(clause_set(_STRICT), clause_set(_OVERLAP)) == "related"   # share comsvcs, neither subset
    assert relation(clause_set(_BASE), clause_set(_DISJOINT)) is None         # no shared field/clause


def test_why_shows_shared_and_unique_clauses():
    j = why(clause_set(_STRICT), clause_set(_BASE))
    assert j["shared"] and j["a_only"]               # strict shares the rundll32 clause, adds comsvcs
    assert not j["b_only"]                            # base has nothing strict lacks


def test_build_lattice_tallies_graded_edges_and_prunes_disjoint():
    lat = build_lattice([_BASE, _STRICT, _SYNONYM, _OVERLAP, _DISJOINT])
    c = lat["counts"]
    assert c.get("exact", 0) >= 1                     # base ⟷ synonym
    assert c.get("broader", 0) + c.get("narrower", 0) >= 1   # base ⟷ strict subsumption
    # the disjoint rule shares no field → no edge to base/strict/synonym
    edges_with_dis = [e for e in lat["edges"] if "dis" in (e[0], e[2])]
    assert all(e[0] == "ov" or e[2] == "ov" or False for e in edges_with_dis) or edges_with_dis == []


def test_exact_classes_are_the_dedup_slice():
    lat = build_lattice([_BASE, _STRICT, _SYNONYM, _OVERLAP, _DISJOINT])
    classes = exact_classes(lat)
    # base and synonym form one exactMatch class; strict (narrower) is NOT collapsed into it
    assert any({"base", "syn"} <= cls for cls in classes)
    assert not any("strict" in cls for cls in classes)        # subsumption ≠ dedup


@pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")
def test_lattice_over_a_real_technique_has_graded_edges():
    """Over real T1003.001 rules: the relation graph has more than just exact edges — broad/narrow/related
    are the navigable order the flat field-set key threw away."""
    from detection.sigma_eval import is_evaluable
    from detection.sigma_panel import gather
    rules = [compile_rule(r) for _p, r in gather("T1003.001", root=SIGMA) if is_evaluable(r)]
    lat = build_lattice(rules)
    assert lat["n_rules"] > 5 and lat["n_edges"] > 0
    # graded, not just dedup: subsumption and/or related edges exist alongside exact
    c = lat["counts"]
    assert sum(c.get(k, 0) for k in ("broader", "narrower", "related")) > 0
