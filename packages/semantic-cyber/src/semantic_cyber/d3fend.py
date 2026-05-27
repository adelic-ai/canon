"""D3FEND loader + local defensive-counters-offensive derivation.

D3FEND.ttl is a mechanics ontology — defensive/offensive techniques are
related to typed artifacts via OWL restrictions (`d3f:may-produce`,
`d3f:monitors`, etc.), not via direct counter triples. The d3fend.mitre.org
API derives the counter relation at query time by matching defensive and
offensive techniques that act on the same artifact (subclass-aware). We
replicate that derivation locally so canon does not need the API at runtime.

Verb lists below are the load-bearing curation: which property paths count
as "offensive action on artifact" vs "defensive action on artifact." They
match the d3fend.mitre.org API's matching rules as of 2026-05-27.

Implementation note: an earlier version used a single SPARQL query with
`rdfs:subClassOf*` on both sides. On the real 3.4MB D3FEND ontology that
query did not return in 20+ minutes — rdflib's SPARQL engine does not
optimize the cross-join. Replaced with direct triple traversal in Python:
collect offensive-touched artifacts via subclass walk, collect defensive
techniques via subclass walk in the other direction, intersect on artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import rdflib

from semantic_core.graph import Graph


D3F = rdflib.Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

OFFENSIVE_RELATIONS: frozenset[rdflib.URIRef] = frozenset(
    {
        D3F["may-produce"],
        D3F["produces"],
        D3F["uses"],
        D3F["modifies"],
        D3F["accesses"],
        D3F["abuses"],
        D3F["invokes"],
        D3F["creates"],
        D3F["executes"],
        D3F["reads"],
        D3F["writes"],
    }
)

DEFENSIVE_RELATIONS: frozenset[rdflib.URIRef] = frozenset(
    {
        D3F["monitors"],
        D3F["analyzes"],
        D3F["filters"],
        D3F["restricts"],
        D3F["hardens"],
        D3F["isolates"],
        D3F["authenticates"],
        D3F["blocks"],
        D3F["detects"],
        D3F["validates"],
        D3F["verifies"],
        D3F["enforces"],
        D3F["quarantines"],
        D3F["identifies"],
    }
)

_RDFS_SUBCLASS = rdflib.RDFS.subClassOf
_RDFS_LABEL = rdflib.RDFS.label
_OWL_ON_PROPERTY = rdflib.OWL.onProperty
_OWL_SOME_FROM = rdflib.OWL.someValuesFrom


@dataclass(frozen=True)
class CounterMatch:
    """One defensive-technique-counters-offensive-technique derivation."""

    defensive: str
    offensive: str
    artifact: str
    offensive_relation: str
    defensive_relation: str
    defensive_label: str | None = None
    artifact_label: str | None = None


def load(path: str | Path) -> Graph:
    """Load d3fend.ttl into a semantic-core Graph."""
    return Graph().load_file(Path(path), format="turtle")


def derive_counters(graph: Graph, attack_technique: str) -> list[CounterMatch]:
    """Find defensive techniques that act on artifacts the attack technique touches.

    `attack_technique` is the local name (e.g. "T1558.003"), the full IRI,
    or an rdflib.URIRef. Subclass-aware on both the offensive side (the
    technique and its specializations) and the defensive side (any subclass
    of d3f:DefensiveTechnique).
    """
    offensive_iri = _resolve_technique_iri(attack_technique)
    g = graph.rdflib_graph

    offensive_classes = _supers_and_self(g, offensive_iri)
    direct_artifacts_to_offensive: dict[
        rdflib.URIRef, list[tuple[rdflib.URIRef, rdflib.URIRef]]
    ] = {}
    for cls in offensive_classes:
        for rel, art in _restrictions(g, cls, OFFENSIVE_RELATIONS):
            direct_artifacts_to_offensive.setdefault(art, []).append((cls, rel))

    if not direct_artifacts_to_offensive:
        return []

    # A defense monitoring a SUPERCLASS of an attack-touched artifact still
    # catches that artifact (a defense monitoring "Credential" covers the
    # attack producing "ServiceTicket" because ServiceTicket is-a Credential).
    # Expand offensive artifacts to their ancestors so the join hits these.
    artifacts_to_offensive: dict[
        rdflib.URIRef, list[tuple[rdflib.URIRef, rdflib.URIRef]]
    ] = {}
    for direct_art, entries in direct_artifacts_to_offensive.items():
        for ancestor in _supers_and_self(g, direct_art):
            artifacts_to_offensive.setdefault(ancestor, []).extend(entries)

    defensive_techniques = _subs_and_self(g, D3F.DefensiveTechnique) - {D3F.DefensiveTechnique}

    matches: list[CounterMatch] = []
    seen: set[tuple] = set()
    for defensive in defensive_techniques:
        for def_rel, art in _restrictions(g, defensive, DEFENSIVE_RELATIONS):
            if art not in artifacts_to_offensive:
                continue
            for _off_cls, off_rel in artifacts_to_offensive[art]:
                key = (defensive, art, off_rel, def_rel)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    CounterMatch(
                        defensive=str(defensive),
                        offensive=str(offensive_iri),
                        artifact=str(art),
                        offensive_relation=str(off_rel),
                        defensive_relation=str(def_rel),
                        defensive_label=_label(g, defensive),
                        artifact_label=_label(g, art),
                    )
                )

    return matches


def defensive_techniques_covering(graph: Graph, attack_technique: str) -> set[str]:
    """Set of defensive technique IRIs whose action covers the attack technique."""
    return {m.defensive for m in derive_counters(graph, attack_technique)}


def _resolve_technique_iri(name: str | rdflib.URIRef) -> rdflib.URIRef:
    if isinstance(name, rdflib.URIRef):
        return name
    if name.startswith("http://") or name.startswith("https://"):
        return rdflib.URIRef(name)
    return D3F[name]


def _supers_and_self(g: rdflib.Graph, cls: rdflib.URIRef) -> set[rdflib.URIRef]:
    seen: set[rdflib.URIRef] = {cls}
    frontier = [cls]
    while frontier:
        c = frontier.pop()
        for sup in g.objects(c, _RDFS_SUBCLASS):
            if isinstance(sup, rdflib.URIRef) and sup not in seen:
                seen.add(sup)
                frontier.append(sup)
    return seen


def _subs_and_self(g: rdflib.Graph, cls: rdflib.URIRef) -> set[rdflib.URIRef]:
    seen: set[rdflib.URIRef] = {cls}
    frontier = [cls]
    while frontier:
        c = frontier.pop()
        for sub in g.subjects(_RDFS_SUBCLASS, c):
            if isinstance(sub, rdflib.URIRef) and sub not in seen:
                seen.add(sub)
                frontier.append(sub)
    return seen


def _restrictions(
    g: rdflib.Graph,
    cls: rdflib.URIRef,
    allowed_relations: Iterable[rdflib.URIRef],
) -> Iterable[tuple[rdflib.URIRef, rdflib.URIRef]]:
    """Yield (relation, artifact) for OWL restrictions attached to `cls` via subClassOf."""
    allowed = set(allowed_relations)
    for restriction in g.objects(cls, _RDFS_SUBCLASS):
        rel = next(iter(g.objects(restriction, _OWL_ON_PROPERTY)), None)
        if rel not in allowed:
            continue
        art = next(iter(g.objects(restriction, _OWL_SOME_FROM)), None)
        if art is None or not isinstance(art, rdflib.URIRef):
            continue
        yield rel, art


def _label(g: rdflib.Graph, subject: rdflib.URIRef) -> str | None:
    label = next(iter(g.objects(subject, _RDFS_LABEL)), None)
    return str(label) if label is not None else None
