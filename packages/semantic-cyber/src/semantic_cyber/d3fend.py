"""D3FEND loader + local defensive-counters-offensive derivation.

D3FEND.ttl is a mechanics ontology — defensive/offensive techniques are
related to typed artifacts via OWL restrictions (e.g. ``d3f:may-produce``,
``d3f:monitors``), not via direct counter triples. The d3fend.mitre.org API
derives the counter relation at query time by matching defensive and
offensive techniques that act on the same artifact (subclass-aware). We
replicate that derivation locally so canon does not need the API at runtime.

How the derivation matches the API (verified 2026-05-27 against 13 techniques
covering 266 defensive matches — see ``design/probes/d3fend/``):

1. **ATT&CK-bounded technique walk.** D3FEND wraps each ATT&CK technique in
   grouping classes (``CredentialAccessTechnique``, ``OffensiveTechnique``,
   ``CyberTechnique``) that carry their own artifact restrictions. The API
   does *not* consume those grouping-class restrictions; it stays inside the
   ATT&CK boundary. We detect that boundary by the presence of the
   ``d3f:attack-id`` property — ATT&CK technique classes carry it, D3FEND's
   grouping classes do not. The walk is bidirectional: a query on a parent
   technique (e.g. T1003) picks up restrictions on its sub-techniques
   (T1003.001 … T1003.008), and a query on a sub-technique (T1558.003) picks
   up restrictions on its ATT&CK parent (T1558).

2. **DigitalArtifact-range filter.** Any OWL restriction on a technique
   whose ``owl:someValuesFrom`` target is a subclass of ``d3f:DigitalArtifact``
   counts as "acts on artifact" — independent of the property (verb). The
   verb is informational, not load-bearing for the join. This naturally
   excludes metadata restrictions like ``enables Tactic`` or
   ``implemented-by Procedure`` where the target isn't an artifact.

3. **Asymmetric artifact-subclass expansion.** An attack-touched artifact is
   expanded UP to its ancestors (a defense ``monitors Credential`` covers an
   attack producing ``ServiceTicket`` because ``ServiceTicket subClassOf
   Credential``). The defensive side is direct lookup — a defense that names
   a narrower artifact than the attack does not widen its scope. The API
   uses the same direction (``sc=-<-`` in its bindings).

Implementation note: an earlier version used a single SPARQL query with
``rdfs:subClassOf*`` on both sides. On the real 3.4MB D3FEND ontology that
query did not return in 20+ minutes — rdflib's SPARQL engine does not
optimize the cross-join. The current implementation traverses triples in
Python directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import rdflib

from semantic_core.graph import Graph


D3F = rdflib.Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

_RDFS_SUBCLASS = rdflib.RDFS.subClassOf
_RDFS_LABEL = rdflib.RDFS.label
_OWL_ON_PROPERTY = rdflib.OWL.onProperty
_OWL_SOME_FROM = rdflib.OWL.someValuesFrom
_ATTACK_ID = D3F["attack-id"]


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

    ``attack_technique`` is the local name (e.g. ``"T1558.003"``), the full
    IRI, or an ``rdflib.URIRef``. The walk stays inside the ATT&CK boundary
    (see module docstring); the artifact filter is structural (any
    ``DigitalArtifact`` subclass); subclass expansion is asymmetric (offensive
    artifacts expand UP to ancestors, defensive artifacts are direct).
    """
    offensive_iri = _resolve_technique_iri(attack_technique)
    g = graph.rdflib_graph
    artifact_set = _subs_and_self(g, D3F.DigitalArtifact)

    offensive_classes = _attack_related(g, offensive_iri)
    if not offensive_classes:
        return []

    direct_artifacts_to_offensive: dict[
        rdflib.URIRef, list[tuple[rdflib.URIRef, rdflib.URIRef]]
    ] = {}
    for cls in offensive_classes:
        for rel, art in _artifact_restrictions(g, cls, artifact_set):
            direct_artifacts_to_offensive.setdefault(art, []).append((cls, rel))

    if not direct_artifacts_to_offensive:
        return []

    # Expand to ancestors so a defense monitoring a SUPERCLASS of an
    # attack-touched artifact still catches it (e.g. defense monitors
    # Credential, attack produces ServiceTicket subClassOf Credential).
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
        for def_rel, art in _artifact_restrictions(g, defensive, artifact_set):
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


def _has_attack_id(g: rdflib.Graph, cls: rdflib.URIRef) -> bool:
    return next(iter(g.objects(cls, _ATTACK_ID)), None) is not None


def _attack_related(g: rdflib.Graph, cls: rdflib.URIRef) -> set[rdflib.URIRef]:
    """Bidirectional ``subClassOf`` walk, restricted to classes carrying ``d3f:attack-id``.

    The API's parent-technique queries pick up sub-technique restrictions
    (e.g. T1003 returns coverage drawn from T1003.001 … T1003.008), and
    sub-technique queries pick up parent restrictions (T1558.003 returns
    coverage drawn from T1558). Both walks stop at the boundary where
    D3FEND's grouping classes take over (no ``attack-id``).
    """
    if not _has_attack_id(g, cls):
        return set()
    seen = {cls}
    frontier = [cls]
    while frontier:
        c = frontier.pop()
        for sup in g.objects(c, _RDFS_SUBCLASS):
            if isinstance(sup, rdflib.URIRef) and sup not in seen and _has_attack_id(g, sup):
                seen.add(sup)
                frontier.append(sup)
        for sub in g.subjects(_RDFS_SUBCLASS, c):
            if isinstance(sub, rdflib.URIRef) and sub not in seen and _has_attack_id(g, sub):
                seen.add(sub)
                frontier.append(sub)
    return seen


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


def _artifact_restrictions(
    g: rdflib.Graph,
    cls: rdflib.URIRef,
    artifact_set: set[rdflib.URIRef],
):
    """Yield (relation, artifact) for OWL restrictions on ``cls`` whose target is an artifact.

    Filter is structural: ``someValuesFrom`` must be a subclass of
    ``d3f:DigitalArtifact``. Property (verb) is yielded for traceability but
    not used to gate the match.
    """
    for restriction in g.objects(cls, _RDFS_SUBCLASS):
        rel = next(iter(g.objects(restriction, _OWL_ON_PROPERTY)), None)
        art = next(iter(g.objects(restriction, _OWL_SOME_FROM)), None)
        if rel is None or art is None or not isinstance(art, rdflib.URIRef):
            continue
        if art not in artifact_set:
            continue
        yield rel, art


def _label(g: rdflib.Graph, subject: rdflib.URIRef) -> str | None:
    label = next(iter(g.objects(subject, _RDFS_LABEL)), None)
    return str(label) if label is not None else None
