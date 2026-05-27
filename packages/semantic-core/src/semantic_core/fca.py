"""Formal Concept Analysis — concept lattice + Duquenne-Guigues implication basis.

A formal context (G, M, I) consists of objects G, attributes M, and an
incidence relation I ⊆ G × M. The derivation operator (·)′ forms a Galois
connection between 2^G and 2^M; its fixed points are formal concepts
(A, B) with A″ = A, B″ = B.

This module provides:
- `FormalContext` — context with cached derivation tables.
- `concepts(ctx)` — enumerate all concepts via Ganter's Next Closure.
- `ConceptLattice(ctx)` — concept lattice satisfying semantic_core.protocols.Lattice.
- `implication_basis(ctx)` — Duquenne-Guigues basis (minimum-size sound +
  complete implication set), computed via Next Closure on pseudo-intents.

The DG basis is the canonical minimum primitive generating set of the
attribute vocabulary — every implication that holds in the context
follows from it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Iterable

import networkx as nx


ObjectId = Hashable
AttributeId = Hashable


@dataclass(frozen=True)
class Concept:
    extent: frozenset
    intent: frozenset


@dataclass(frozen=True)
class Implication:
    premise: frozenset
    conclusion: frozenset

    def __repr__(self) -> str:
        prem = "{" + ", ".join(map(str, sorted(self.premise, key=str))) + "}"
        conc = "{" + ", ".join(map(str, sorted(self.conclusion, key=str))) + "}"
        return f"{prem} → {conc}"


class FormalContext:
    """Formal context with cached derivation tables.

    Attribute ORDER is preserved as given — Next Closure depends on a
    linear order on M to enumerate closed sets lexicographically.
    """

    def __init__(
        self,
        objects: Iterable[ObjectId],
        attributes: Iterable[AttributeId],
        incidence: Iterable[tuple[ObjectId, AttributeId]],
    ) -> None:
        self._objects: tuple = tuple(objects)
        self._attributes: tuple = tuple(attributes)
        self._attr_index: dict = {m: i for i, m in enumerate(self._attributes)}

        incidence_set = frozenset(incidence)

        attr_set = set(self._attributes)
        obj_set = set(self._objects)
        for g, m in incidence_set:
            if g not in obj_set:
                raise ValueError(f"incidence references unknown object: {g!r}")
            if m not in attr_set:
                raise ValueError(f"incidence references unknown attribute: {m!r}")

        self._obj_attrs: dict = {
            g: frozenset(m for m in self._attributes if (g, m) in incidence_set)
            for g in self._objects
        }
        self._attr_objs: dict = {
            m: frozenset(g for g in self._objects if (g, m) in incidence_set)
            for m in self._attributes
        }

    @property
    def objects(self) -> tuple:
        return self._objects

    @property
    def attributes(self) -> tuple:
        return self._attributes

    def has(self, obj: ObjectId, attr: AttributeId) -> bool:
        return attr in self._obj_attrs.get(obj, frozenset())

    def derive_attrs(self, objs: Iterable[ObjectId]) -> frozenset:
        """A′ = {m ∈ M : ∀g ∈ A, gIm}."""
        objs = tuple(objs)
        if not objs:
            return frozenset(self._attributes)
        result = self._obj_attrs[objs[0]]
        for g in objs[1:]:
            result = result & self._obj_attrs[g]
            if not result:
                break
        return result

    def derive_objs(self, attrs: Iterable[AttributeId]) -> frozenset:
        """B′ = {g ∈ G : ∀m ∈ B, gIm}."""
        attrs = tuple(attrs)
        if not attrs:
            return frozenset(self._objects)
        result = self._attr_objs[attrs[0]]
        for m in attrs[1:]:
            result = result & self._attr_objs[m]
            if not result:
                break
        return result

    def close_attrs(self, attrs: Iterable[AttributeId]) -> frozenset:
        """B″ = closure on the attribute side."""
        return self.derive_attrs(self.derive_objs(attrs))


def _next_closure(
    A: frozenset,
    attributes: tuple,
    attr_index: dict,
    closure,
) -> frozenset | None:
    """Ganter's Next Closure: next lex-greater closed set after A, or None."""
    n = len(attributes)
    current = set(A)
    for i in range(n - 1, -1, -1):
        m = attributes[i]
        if m in current:
            current.discard(m)
        else:
            candidate = closure(frozenset(current | {m}))
            new_elements = candidate - current - {m}
            if all(attr_index[mj] >= i for mj in new_elements):
                return candidate
    return None


def concepts(ctx: FormalContext) -> list[Concept]:
    """Enumerate all formal concepts of `ctx`."""
    result: list[Concept] = []
    intent: frozenset | None = ctx.close_attrs(frozenset())

    while intent is not None:
        result.append(Concept(extent=ctx.derive_objs(intent), intent=intent))
        intent = _next_closure(intent, ctx.attributes, ctx._attr_index, ctx.close_attrs)

    return result


class ConceptLattice:
    """Concept lattice — Lattice Protocol with join/meet via Galois closure.

    leq follows the convention c1 ≤ c2 iff extent(c1) ⊆ extent(c2)
    (equivalently iff intent(c1) ⊇ intent(c2)). The Hasse diagram is
    materialized as a NetworkX DiGraph for downstream graph queries.
    """

    def __init__(self, ctx: FormalContext) -> None:
        self._ctx = ctx
        self._concepts = concepts(ctx)
        self._by_intent: dict[frozenset, Concept] = {c.intent: c for c in self._concepts}
        self._hasse: nx.DiGraph = self._build_hasse()

    @property
    def context(self) -> FormalContext:
        return self._ctx

    @property
    def hasse(self) -> nx.DiGraph:
        """Hasse diagram (edges only between immediate covers)."""
        return self._hasse

    def elements(self) -> Iterable[Concept]:
        return tuple(self._concepts)

    def leq(self, a: Concept, b: Concept) -> bool:
        return a.extent <= b.extent

    def join(self, a: Concept, b: Concept) -> Concept:
        intent = self._ctx.close_attrs(a.intent & b.intent)
        return self._by_intent[intent]

    def meet(self, a: Concept, b: Concept) -> Concept:
        extent = a.extent & b.extent
        intent = self._ctx.derive_attrs(extent)
        return self._by_intent[intent]

    def top(self) -> Concept:
        return max(self._concepts, key=lambda c: len(c.extent))

    def bottom(self) -> Concept:
        return min(self._concepts, key=lambda c: len(c.extent))

    def _build_hasse(self) -> nx.DiGraph:
        g = nx.DiGraph()
        for c in self._concepts:
            g.add_node(c)

        # Reachability via full ≤ relation, then transitive reduction.
        full = nx.DiGraph()
        full.add_nodes_from(self._concepts)
        for a in self._concepts:
            for b in self._concepts:
                if a is b:
                    continue
                if a.extent < b.extent:
                    full.add_edge(a, b)

        return nx.transitive_reduction(full) if full.number_of_edges() else g


def implication_basis(ctx: FormalContext) -> list[Implication]:
    """Duquenne-Guigues basis — pseudo-intents + their closures.

    A pseudo-intent P satisfies P ≠ P″ and P contains the closure (under
    the current basis) of every pseudo-intent that's a proper subset of P.
    The DG basis is {P → P″ \\ P : P pseudo-intent}. It is sound, complete,
    and minimum-size for the implications holding in `ctx`.

    Algorithm: Next Closure on the L-closure operator (closure under
    current basis ∪ input set). Each L-closed set that is not also (·)″-
    closed is a pseudo-intent; emit an implication and continue.
    """
    basis: list[Implication] = []

    def L_closure(A: frozenset) -> frozenset:
        B = set(A)
        changed = True
        while changed:
            changed = False
            for imp in basis:
                if imp.premise <= B and not imp.conclusion <= B:
                    B |= imp.conclusion
                    changed = True
        return frozenset(B)

    P: frozenset | None = L_closure(frozenset())
    while P is not None:
        P_close = ctx.close_attrs(P)
        if P != P_close:
            basis.append(Implication(premise=P, conclusion=P_close - P))
        P = _next_closure(P, ctx.attributes, ctx._attr_index, L_closure)

    return basis
