"""Cross-framework SKOS bridge helpers.

A Bridge is a typed mapping between two concept schemes — e.g.
Sigma→D3FEND or OCSF→ATT&CK. Published frameworks don't ship these
links; they are the curation work that gives the unified concept lattice
its shape.

Two concrete sources:
- `DictBridge` — in-memory mapping built from curated dict.
- `bridges_from_graph` — read skos:exactMatch / skos:closeMatch /
  skos:broadMatch triples out of an RDF graph already loaded with
  multiple framework vocabularies.

`compose(a→b, b→c) → a→c` chains bridges. `invert(a→b) → b→a` reverses.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import rdflib

from semantic_core.graph import Graph
from semantic_core.protocols import Bridge, ConceptId


SKOS = rdflib.Namespace("http://www.w3.org/2004/02/skos/core#")

MATCH_PREDICATES = {
    SKOS.exactMatch,
    SKOS.closeMatch,
    SKOS.broadMatch,
    SKOS.narrowMatch,
    SKOS.relatedMatch,
}


class DictBridge:
    """Bridge backed by a {source_id: [target_ids]} dict."""

    def __init__(
        self,
        source_scheme: str,
        target_scheme: str,
        mappings: dict[ConceptId, Iterable[ConceptId]] | None = None,
    ) -> None:
        self.source_scheme = source_scheme
        self.target_scheme = target_scheme
        self._mappings: dict[ConceptId, list[ConceptId]] = {
            k: list(v) for k, v in (mappings or {}).items()
        }

    def map(self, source_id: ConceptId) -> Iterable[ConceptId]:
        return tuple(self._mappings.get(source_id, ()))

    def sources(self) -> Iterable[ConceptId]:
        return tuple(self._mappings.keys())

    def __len__(self) -> int:
        return sum(len(v) for v in self._mappings.values())


def compose(first: Bridge, second: Bridge) -> DictBridge:
    """(a→b) ∘ (b→c) → a→c. Sources/targets reach all transitively-mapped targets."""
    if first.target_scheme != second.source_scheme:
        raise ValueError(
            f"cannot compose: first.target={first.target_scheme!r} "
            f"!= second.source={second.source_scheme!r}"
        )

    composed: dict[ConceptId, list[ConceptId]] = {}
    sources = first.sources() if hasattr(first, "sources") else ()
    for s in sources:
        targets = []
        seen = set()
        for mid in first.map(s):
            for t in second.map(mid):
                if t not in seen:
                    seen.add(t)
                    targets.append(t)
        if targets:
            composed[s] = targets

    return DictBridge(first.source_scheme, second.target_scheme, composed)


def invert(bridge: Bridge) -> DictBridge:
    """Flip direction. One-to-many in the original becomes many-to-one (collapsed) here."""
    inverted: dict[ConceptId, list[ConceptId]] = defaultdict(list)
    sources = bridge.sources() if hasattr(bridge, "sources") else ()
    for s in sources:
        for t in bridge.map(s):
            if s not in inverted[t]:
                inverted[t].append(s)

    return DictBridge(bridge.target_scheme, bridge.source_scheme, dict(inverted))


def bridges_from_graph(
    graph: Graph | rdflib.Graph,
    source_scheme: str,
    target_scheme: str,
    predicates: Iterable[rdflib.URIRef] = (SKOS.exactMatch, SKOS.closeMatch),
) -> DictBridge:
    """Extract SKOS match triples whose IRIs fall under the two schemes.

    Membership is decided by prefix — concept IRIs are expected to start with
    their scheme IRI. Tighter scheme membership (skos:inScheme) is a
    second-pass refinement; not done here.
    """
    rdfg = graph.rdflib_graph if isinstance(graph, Graph) else graph

    mappings: dict[ConceptId, list[ConceptId]] = defaultdict(list)
    for pred in predicates:
        for s, o in rdfg.subject_objects(pred):
            s_str, o_str = str(s), str(o)
            if s_str.startswith(source_scheme) and o_str.startswith(target_scheme):
                if o_str not in mappings[s_str]:
                    mappings[s_str].append(o_str)
            elif o_str.startswith(source_scheme) and s_str.startswith(target_scheme):
                if s_str not in mappings[o_str]:
                    mappings[o_str].append(s_str)

    return DictBridge(source_scheme, target_scheme, dict(mappings))
