"""The SKOS-graded rule-relation lattice — stage 3 of the treatment pipeline.

Two rules don't just dedup (same / not-same); they relate by a **graded edge** (the
[[rule_classification_skos]] reframe): ``exactMatch`` (synonym = the dedup slice), ``broadMatch`` /
``narrowMatch`` (subsumption — a *navigable* partial order, not a collapse), ``relatedMatch`` (overlap).
This module computes that relation across a whole corpus, generalizing ``admission.structural_relation``
(which does one pair, on a ``MotifGraph``) to every rule, on the ``CompiledRule`` IR.

**Structural, earned by contents** (the ``__subclasshook__`` axis — not the lossy ATT&CK tag). The relation
is read from each rule's **positive-selection clause-set** (its `+1` blocks; filters/exclusions are a
separate axis, deferred): a rule with MORE positive clauses is *stricter* → matches a *subset* of events →
the **narrower** concept (extensional semantics). So:

```
clause-sets equal         → exactMatch    (synonym; this is "dedup")     skos:exactMatch
a ⊃ b  (a has more)       → a narrower b  (a stricter, matches subset)   skos:narrowMatch
a ⊂ b  (a has fewer)      → a broader  b  (a more general)               skos:broadMatch
overlap, neither subset   → relatedMatch                                  skos:relatedMatch
no shared clause          → (no edge)
```

Conservative on exact ``(field, mods, values)`` tuples — never *false-claims* a synonym (different values ≠
synonym). It is a **structural** proxy: the grounded truth (do two rules catch the same labeled instances)
is the catch-set, stage 4. This lattice is what catch-set later *grounds*; corpus-free, not gated.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict

from detection.atom_index import block_polarities
from detection.rule_ir import CompiledRule

# relation of A relative to B → its SKOS mapping predicate
SKOS = {"exact": "skos:exactMatch", "close": "skos:closeMatch", "narrower": "skos:narrowMatch",
        "broader": "skos:broadMatch", "related": "skos:relatedMatch"}

# tightness above this band promotes a "related" edge to "close" (skos:closeMatch). Tunable.
CLOSE_BAND = 0.6


def clause_set(ir: CompiledRule) -> frozenset[tuple]:
    """A rule's **positive-selection** clause-set — the ``(field, mods, values)`` tuples of its `+1` blocks
    (the discriminators it matches *on*). Filter/exclusion (`-1`) blocks are left out: they narrow the rule
    on a different axis (a future refinement). Keyword blocks have no field and are skipped, so a
    keyword-only rule yields the empty set and is excluded from the lattice (it has no comparable structure)."""
    pol = block_polarities(ir)
    out: set[tuple] = set()
    for b in ir.blocks:
        if b.kind == "keyword":
            continue
        if 1 in pol.get(b.name, {1}):                          # positive block (selector), default positive
            for m in b.maps:
                for c in m:
                    out.add((c.field, c.mods, c.values))
    return frozenset(out)


def relation(a: frozenset, b: frozenset) -> str | None:
    """The relation of clause-set ``a`` relative to ``b`` (extensional: more clauses = stricter = narrower).
    ``None`` if disjoint (no edge) or either side is empty (unstructured)."""
    if not a or not b:
        return None
    if a == b:
        return "exact"
    if a > b:
        return "narrower"
    if a < b:
        return "broader"
    return "related" if (a & b) else None


def clause_idf(rules: list[CompiledRule]) -> dict[tuple, float]:
    """Per-clause inverse document frequency over the corpus: ``log(N / df)`` where ``df`` is how many rules
    contain the clause. A clause in *few* rules is specific/informative (high IDF); a ubiquitous clause
    (``Image|endswith \\rundll32.exe``) is generic (low IDF). This is the weight that makes tightness an
    information measure rather than a raw count."""
    n = len(rules)
    df: Counter = Counter()
    for ir in rules:
        for c in clause_set(ir):
            df[c] += 1
    return {c: math.log(n / d) for c, d in df.items()} if n else {}


def _weight(clauses: frozenset, idf: dict | None) -> float:
    """Mass of a clause-set: its size (cardinality) if unweighted, else the sum of clause IDFs (information)."""
    if idf is None:
        return float(len(clauses))
    return sum(idf.get(c, 1.0) for c in clauses)


def tightness(a: frozenset, b: frozenset, idf: dict | None = None) -> float:
    """Graded overlap of two clause-sets in [0, 1] — the *tightness* axis SKOS needs (exact/close/loose),
    distinct from the position axis (broad/narrow). Weighted Jaccard: ``mass(a∩b) / mass(a∪b)``.

    With ``idf=None`` it is plain Jaccard (cardinality — how *many* clauses shared). With per-clause IDF
    weights it is the **information** version: sharing a rare, discriminating clause counts far more than
    sharing a ubiquitous one — the entropy-analog (the same cardinality-vs-distribution complementarity as
    fan-out's distinct⟷entropy). 1.0 = identical, 0.0 = disjoint."""
    union = a | b
    if not union:
        return 0.0
    return _weight(a & b, idf) / _weight(union, idf)


def why(a: frozenset, b: frozenset) -> dict:
    """The justification for an edge, shown on demand: the shared clauses and what each side has uniquely."""
    return {"shared": sorted(map(str, a & b)),
            "a_only": sorted(map(str, a - b)),
            "b_only": sorted(map(str, b - a))}


def build_lattice(rules: list[CompiledRule]) -> dict:
    """Compute the graded relation graph over ``rules``. An inverted index (field → rules) restricts the
    pairwise comparison to rules that share ≥1 field (everything else is disjoint = no edge), so it is
    near-linear in practice, not O(n²). Returns the edges ``(rule_a, relation, rule_b)`` and the type tally;
    ``exact`` edges are the dedup (synonym) classes, ``broader``/``narrower`` the navigable subsumption order."""
    sets = [(ir.rule_id, clause_set(ir)) for ir in rules]
    sets = [(rid, cs) for rid, cs in sets if cs]               # drop unstructured (keyword-only) rules
    idx: dict[str, set[int]] = defaultdict(set)
    for i, (_rid, cs) in enumerate(sets):
        for (f, _m, _v) in cs:
            idx[f].add(i)

    idf = clause_idf(rules)                                    # information weights for the tightness grade
    edges: list[tuple] = []
    counts: Counter = Counter()
    for i, (rid_a, a) in enumerate(sets):
        candidates: set[int] = set()
        for (f, _m, _v) in a:
            candidates |= idx[f]
        for j in candidates:
            if j <= i:                                         # each unordered pair once
                continue
            rid_b, b = sets[j]
            rel = relation(a, b)
            if rel is None:
                continue
            t = round(tightness(a, b, idf), 3)
            if rel == "related" and t >= CLOSE_BAND:           # tightness GRADES the overlap web
                rel = "close"
            edges.append((rid_a, rel, rid_b, t))               # edges now carry their tightness
            counts[rel] += 1
    return {"n_rules": len(sets), "n_edges": len(edges), "counts": dict(counts), "edges": edges}


def exact_classes(lattice: dict) -> list[set[str]]:
    """The dedup classes = connected components under ``exactMatch`` edges (synonym equivalence classes).
    Everything else (broader/narrower/related) is the navigable order, NOT a collapse."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        parent[find(x)] = find(y)

    nodes: set[str] = set()
    for a, rel, b, *_ in lattice["edges"]:
        nodes.add(a); nodes.add(b)
        if rel == "exact":
            union(a, b)
    groups: dict[str, set[str]] = defaultdict(set)
    for n in nodes:
        groups[find(n)].add(n)
    return [g for g in groups.values() if len(g) > 1]
