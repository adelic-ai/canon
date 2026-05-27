"""fca.py — formal concept analysis, concept lattice, DG implication basis.

Test contexts mostly small and hand-verifiable. The "animals" context is a
classic FCA textbook example used to sanity-check the algorithms.
"""

from __future__ import annotations

import pytest

from semantic_core.fca import (
    Concept,
    ConceptLattice,
    FormalContext,
    Implication,
    concepts,
    implication_basis,
)
from semantic_core.protocols import Lattice


def _animals() -> FormalContext:
    """Classic FCA example — objects are animals, attributes are features."""
    objs = ("dove", "hen", "duck", "goose", "owl", "hawk", "eagle")
    attrs = ("flies", "swims", "predator", "bird")
    incidence = [
        ("dove", "flies"), ("dove", "bird"),
        ("hen", "bird"),
        ("duck", "flies"), ("duck", "swims"), ("duck", "bird"),
        ("goose", "flies"), ("goose", "swims"), ("goose", "bird"),
        ("owl", "flies"), ("owl", "predator"), ("owl", "bird"),
        ("hawk", "flies"), ("hawk", "predator"), ("hawk", "bird"),
        ("eagle", "flies"), ("eagle", "predator"), ("eagle", "bird"),
    ]
    return FormalContext(objs, attrs, incidence)


def _tiny() -> FormalContext:
    """3 objects × 3 attributes, hand-verifiable."""
    return FormalContext(
        objects=("o1", "o2", "o3"),
        attributes=("a", "b", "c"),
        incidence=[("o1", "a"), ("o1", "b"), ("o2", "b"), ("o2", "c"), ("o3", "a")],
    )


def test_context_rejects_unknown_object():
    with pytest.raises(ValueError, match="unknown object"):
        FormalContext(("o1",), ("a",), [("o2", "a")])


def test_context_rejects_unknown_attribute():
    with pytest.raises(ValueError, match="unknown attribute"):
        FormalContext(("o1",), ("a",), [("o1", "b")])


def test_derivation_operators():
    ctx = _animals()
    assert ctx.derive_attrs(("dove",)) == frozenset({"flies", "bird"})
    assert ctx.derive_attrs(("dove", "duck")) == frozenset({"flies", "bird"})
    assert ctx.derive_objs(("predator",)) == frozenset({"owl", "hawk", "eagle"})
    assert ctx.derive_objs(("predator", "swims")) == frozenset()


def test_empty_object_set_derives_all_attributes():
    ctx = _tiny()
    assert ctx.derive_attrs(()) == frozenset({"a", "b", "c"})


def test_empty_attribute_set_derives_all_objects():
    ctx = _tiny()
    assert ctx.derive_objs(()) == frozenset({"o1", "o2", "o3"})


def test_close_attrs_is_idempotent():
    ctx = _animals()
    once = ctx.close_attrs(frozenset({"predator"}))
    twice = ctx.close_attrs(once)
    assert once == twice
    assert "bird" in once and "flies" in once  # all predators fly and are birds


def test_concepts_returns_closed_pairs():
    ctx = _tiny()
    cs = concepts(ctx)
    for c in cs:
        assert ctx.derive_attrs(c.extent) == c.intent
        assert ctx.derive_objs(c.intent) == c.extent


def test_concepts_includes_top_and_bottom():
    """Top = (all objects, common attrs); bottom = (∅-or-all-no-attrs, all attrs)."""
    ctx = _tiny()
    cs = concepts(ctx)
    extents = [c.extent for c in cs]
    intents = [c.intent for c in cs]
    assert frozenset({"o1", "o2", "o3"}) in extents
    assert frozenset({"a", "b", "c"}) in intents


def test_concept_count_matches_hand_enumeration():
    """4-attr animals context has exactly these 5 concepts:
    (all, {bird}) — universal common attr
    (all except hen, {flies, bird})
    ({owl, hawk, eagle}, {flies, predator, bird})
    ({duck, goose}, {flies, swims, bird})
    (∅, {all four attrs}) — bottom
    """
    cs = concepts(_animals())
    assert len(cs) == 5


def test_concept_lattice_satisfies_protocol():
    lat = ConceptLattice(_animals())
    assert isinstance(lat, Lattice)


def test_lattice_leq_is_extent_subset():
    lat = ConceptLattice(_animals())
    predators = next(c for c in lat.elements() if c.intent == frozenset({"flies", "predator", "bird"}))
    flyers = next(c for c in lat.elements() if c.intent == frozenset({"flies", "bird"}))
    assert lat.leq(predators, flyers)
    assert not lat.leq(flyers, predators)


def test_lattice_join_meet_are_valid_concepts():
    lat = ConceptLattice(_animals())
    elements = list(lat.elements())
    for a in elements:
        for b in elements:
            j = lat.join(a, b)
            m = lat.meet(a, b)
            assert j in elements
            assert m in elements
            assert lat.leq(a, j) and lat.leq(b, j)
            assert lat.leq(m, a) and lat.leq(m, b)


def test_lattice_join_meet_absorption():
    """a ∨ (a ∧ b) = a, a ∧ (a ∨ b) = a."""
    lat = ConceptLattice(_tiny())
    elements = list(lat.elements())
    for a in elements:
        for b in elements:
            assert lat.join(a, lat.meet(a, b)) == a
            assert lat.meet(a, lat.join(a, b)) == a


def test_top_and_bottom_are_unique():
    lat = ConceptLattice(_animals())
    top = lat.top()
    bot = lat.bottom()
    for c in lat.elements():
        assert lat.leq(c, top)
        assert lat.leq(bot, c)


def test_hasse_has_no_transitive_edges():
    lat = ConceptLattice(_animals())
    h = lat.hasse
    for a, b in h.edges():
        for c in h.successors(a):
            if c is b:
                continue
            # if a→c and c→b in Hasse, then a→b is a transitive edge and shouldn't exist
            assert not h.has_edge(c, b)


def test_implication_basis_is_sound():
    """Every implication in the basis must hold in the context."""
    ctx = _animals()
    basis = implication_basis(ctx)
    for imp in basis:
        # P → C means: every object with all of P has all of C
        for g in ctx.objects:
            attrs = ctx.derive_attrs((g,))
            if imp.premise <= attrs:
                assert imp.conclusion <= attrs, f"{imp} fails on {g}"


def test_implication_basis_entails_predator_flies_bird():
    """The DG basis is minimum-size — {predator} → {flies, bird} need NOT appear
    verbatim if {} → {bird} is already present (it makes {predator} → {bird}
    redundant). What we check is the closure: under the basis,
    {predator} should L-close to a superset containing flies and bird.
    """
    ctx = _animals()
    basis = implication_basis(ctx)

    def L_closure(A):
        B = set(A)
        changed = True
        while changed:
            changed = False
            for imp in basis:
                if imp.premise <= B and not imp.conclusion <= B:
                    B |= imp.conclusion
                    changed = True
        return frozenset(B)

    closure_of_predator = L_closure(frozenset({"predator"}))
    assert "flies" in closure_of_predator
    assert "bird" in closure_of_predator


def test_implication_basis_is_complete():
    """Closure under basis equals (·)'' closure for every closed set."""
    ctx = _animals()
    basis = implication_basis(ctx)

    def L_closure(A):
        B = set(A)
        changed = True
        while changed:
            changed = False
            for imp in basis:
                if imp.premise <= B and not imp.conclusion <= B:
                    B |= imp.conclusion
                    changed = True
        return frozenset(B)

    # Sample: closure of every singleton attribute set
    for m in ctx.attributes:
        A = frozenset({m})
        assert L_closure(A) == ctx.close_attrs(A), f"basis incomplete on {{{m}}}"


def test_empty_context():
    ctx = FormalContext(objects=(), attributes=(), incidence=[])
    cs = concepts(ctx)
    assert len(cs) == 1
    assert cs[0].extent == frozenset()
    assert cs[0].intent == frozenset()
    assert implication_basis(ctx) == []
