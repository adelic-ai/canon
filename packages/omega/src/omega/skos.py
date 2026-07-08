"""Stage 4 — SKOS graded relations: name the order FCA derived, and grade the overlap.

Two rules don't merely dedup (same / not-same); they *relate* by a graded edge over their attribute-sets
under a chosen projection:

    equal sets          exactMatch     (synonym at this projection = the FCA concept)
    a ⊃ b  (a stricter) narrowMatch    (a is narrower — a superset intent -> a subset of events)
    a ⊂ b               broadMatch
    overlap, neither ⊆  relatedMatch   (promoted to closeMatch when the overlap is tight enough)
    disjoint            (no edge)

The *position* axis (broad/narrow) is the ⊆-order from :func:`omega.fca.subsumes`; the *tightness* axis
(exact/close/loose) is a weighted Jaccard, optionally IDF-weighted so sharing a RARE token counts more than a
ubiquitous one. Every edge can show its ``why`` (shared tokens + what each side has uniquely). Serialises to a
SKOS RDF (Turtle) graph — the queryable product.

Ruleset-agnostic and parametric: the relation is over ``attributes(rule, axes)`` for whatever ``axes`` you
choose, so it grades the same refinement-tower level FCA grouped. Ported from canon's ``detection.rule_lattice``,
re-homed onto omega's token-sets.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from omega.axes import CONTENT, attributes
from omega.ir import CompiledRule

SKOS = {"exact": "skos:exactMatch", "close": "skos:closeMatch", "narrower": "skos:narrowMatch",
        "broader": "skos:broadMatch", "related": "skos:relatedMatch"}

CLOSE_BAND = 0.6            # a related edge this tight or tighter is promoted to closeMatch


@dataclass(frozen=True)
class Edge:
    """A graded relation of ``a`` *relative to* ``b`` (so ``narrower`` means a is narrower than b), with the
    tightness of their overlap in [0, 1]. ``skos`` is the mapped predicate."""

    a: str
    rel: str
    b: str
    tightness: float

    @property
    def skos(self) -> str:
        return SKOS[self.rel]


def relation(a: frozenset[str], b: frozenset[str]) -> str | None:
    """The relation of token-set ``a`` relative to ``b``. ``None`` if disjoint (no edge) or either is empty."""
    if not a or not b:
        return None
    if a == b:
        return "exact"
    if a > b:
        return "narrower"
    if a < b:
        return "broader"
    return "related" if (a & b) else None


def token_idf(rules: list[CompiledRule], axes: frozenset[str] | set[str]) -> dict[str, float]:
    """Per-token inverse document frequency ``log(N/df)`` over the corpus at this projection — a token in few
    rules is discriminating (high), a ubiquitous one is generic (low). The weight that makes tightness an
    information measure rather than a raw count."""
    axes = frozenset(axes)
    n = len(rules)
    df: Counter = Counter()
    for r in rules:
        for tok in attributes(r, axes=axes):
            df[tok] += 1
    return {tok: math.log(n / d) for tok, d in df.items()} if n else {}


def _mass(tokens: frozenset[str], idf: dict[str, float] | None) -> float:
    return float(len(tokens)) if idf is None else sum(idf.get(t, 1.0) for t in tokens)


def tightness(a: frozenset[str], b: frozenset[str], idf: dict[str, float] | None = None) -> float:
    """Graded overlap in [0, 1] — weighted Jaccard ``mass(a∩b) / mass(a∪b)``. ``idf=None`` is plain
    (cardinality) Jaccard; with IDF weights, sharing a rare token counts far more. 1.0 identical, 0.0 disjoint."""
    union = a | b
    if not union:
        return 0.0
    denom = _mass(union, idf)
    if denom == 0.0:
        return 1.0 if a == b else len(a & b) / len(union)
    return _mass(a & b, idf) / denom


def why(a: frozenset[str], b: frozenset[str]) -> dict[str, list[str]]:
    """The justification for an edge, shown on demand: shared tokens, and what each side has uniquely."""
    return {"shared": sorted(a & b), "a_only": sorted(a - b), "b_only": sorted(b - a)}


def relate(rules: list[CompiledRule], *, axes: frozenset[str] | set[str] = CONTENT,
           close_band: float = CLOSE_BAND, idf_weighted: bool = True) -> list[Edge]:
    """The graded relation graph over ``rules`` at the ``axes`` projection. An inverted index (token → rules)
    limits comparison to rules sharing ≥1 token — disjoint pairs are no-edge by definition, so this is far
    below O(n²) in practice. Rules with no tokens at this projection are dropped (no comparable structure).
    Deterministic order."""
    axes = frozenset(axes)
    sets = [(r.id or f"__anon_{i}", attributes(r, axes=axes)) for i, r in enumerate(rules)]
    sets = [(rid, toks) for rid, toks in sets if toks]
    idf = token_idf(rules, axes) if idf_weighted else None

    index: dict[str, list[int]] = defaultdict(list)
    for i, (_rid, toks) in enumerate(sets):
        for tok in toks:
            index[tok].append(i)

    edges: list[Edge] = []
    for i, (rid_a, a) in enumerate(sets):
        candidates = {j for tok in a for j in index[tok] if j > i}      # each unordered pair once
        for j in candidates:
            rid_b, b = sets[j]
            rel = relation(a, b)
            if rel is None:
                continue
            t = round(tightness(a, b, idf), 3)
            if rel == "related" and t >= close_band:
                rel = "close"
            edges.append(Edge(rid_a, rel, rid_b, t))
    return edges


def counts(edges: list[Edge]) -> dict[str, int]:
    """Tally edges by relation kind — exact (dedup), broader/narrower (subsumption), close/related (overlap)."""
    return dict(Counter(e.rel for e in edges))


def to_turtle(edges: list[Edge], *, prefix: str = "urn:omega:rule:") -> str:
    """Emit the graded lattice as a SKOS RDF (Turtle) graph — each edge a ``skos:*Match`` triple between two
    rule IRIs. Dependency-free string emit. Query it, e.g. ``?a skos:broadMatch ?b`` for the subsumption
    skeleton. (Tightness is an edge property; annotating it needs RDF-star/reification — deferred.)"""
    out = ["@prefix skos: <http://www.w3.org/2004/02/skos/core#> .", f"@prefix : <{prefix}> .", ""]
    for e in edges:
        out.append(f":{e.a} {e.skos} :{e.b} .")
    return "\n".join(out) + "\n"
