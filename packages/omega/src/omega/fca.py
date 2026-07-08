"""Stage 3 — FCA: derive the concept structure from rules and a chosen attribute projection.

Formal Concept Analysis, at the grain the essay actually uses: group rules by their attribute-set into
**concepts**, and read the ⊆-order between attribute-sets as the **broader/narrower** subsumption lattice
(a rule with MORE attributes is stricter → the *narrower* concept). This is the tractable partition + order,
not the full (exponential) Galois lattice — a deliberate cut, flagged.

The projection is a PARAMETER (``axes``), never a hardcoded key. "Same?" is a family of relations indexed by
the axis-set: :func:`concepts` computes the structure at *one* level of that refinement tower. Fewer axes =
coarser = a quotient of finer. Ruleset-agnostic — reads the IR through :func:`omega.axes.attributes`.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from omega.axes import CONTENT, attributes
from omega.ir import CompiledRule


@dataclass(frozen=True)
class Concept:
    """One FCA concept under a projection: the shared attribute-set (the *intent*) and the rule ids that have
    exactly it (the *extent*). ``size`` is how many rules collapsed here — ``> 1`` means the projection judges
    them the same, which is the over-collapse when the projection is coarse."""

    attributes: frozenset[str]
    members: tuple[str, ...]

    @property
    def size(self) -> int:
        return len(self.members)


@dataclass(frozen=True)
class Lattice:
    """The concept structure over a rule set under one ``axes`` projection: the concepts plus the counts that
    quantify collapse. ``n_rules`` vs ``n_concepts`` is the over-collapse ratio; ``collapsed`` lists the
    many-rule concepts (the interesting ones)."""

    axes: frozenset[str]
    n_rules: int
    concepts: tuple[Concept, ...]

    @property
    def n_concepts(self) -> int:
        return len(self.concepts)

    @property
    def collapsed(self) -> tuple[Concept, ...]:
        """Concepts holding more than one rule — where the projection calls distinct rules "the same"."""
        return tuple(c for c in self.concepts if c.size > 1)


def concepts(rules: list[CompiledRule], *, axes: frozenset[str] | set[str] = CONTENT) -> Lattice:
    """Group ``rules`` into FCA concepts under the ``axes`` projection. Rules with no attributes under the
    projection (e.g. a keyword-only rule seen through the ``field`` axis) share the empty attribute-set and so
    form one concept — reported, not dropped. Deterministic: concepts are ordered by descending size then by
    a stable key. ``axes`` is the projection; nothing here privileges a particular one."""
    axes = frozenset(axes)
    buckets: dict[frozenset[str], list[str]] = defaultdict(list)
    for i, r in enumerate(rules):
        attrs = attributes(r, axes=axes)
        buckets[attrs].append(r.id or f"__anon_{i}")

    cs = tuple(
        Concept(attributes=attrs, members=tuple(sorted(members)))
        for attrs, members in buckets.items()
    )
    cs = tuple(sorted(cs, key=lambda c: (-c.size, tuple(sorted(c.attributes)))))
    return Lattice(axes=axes, n_rules=len(rules), concepts=cs)


def subsumes(a: Concept, b: Concept) -> bool:
    """True iff concept ``a`` is *narrower than or equal to* ``b`` — ``a`` has all of ``b``'s attributes and
    more (a superset intent → a stricter rule → a subset of events). The ⊆-order that IS SKOS broader/narrower;
    Stage 4 turns these into graded edges."""
    return b.attributes <= a.attributes
