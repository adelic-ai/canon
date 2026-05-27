"""owlready2 wrapper for OWL DL entailment.

owlready2 stores reasoner output in its own World/Ontology structures,
NOT in a graph view. `world.as_rdflib_graph()` returns only asserted
triples; inferred class membership lives on `Class.ancestors()` and
`Individual.INDIRECT_is_a`. So the wrapper's primary surface is a
`Reasoned` query object, not a graph round-trip. `materialize()` is
available for callers that want inferences as RDF triples.

owlready2 0.46–0.50 ship a longstanding API mismatch: `triplelite.Graph.save`
forwards all kwargs into `driver._save`, which only accepts `filter`. The
reasoner passes `commit=False` and the call blows up with a TypeError.
Patched at module import — strip kwargs `_save` doesn't accept.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Literal

import owlready2
import rdflib
from owlready2 import triplelite

from semantic_core.graph import Graph


def _patch_triplelite_save() -> None:
    _ALLOWED = {"filter"}
    original = triplelite.Graph.save

    if getattr(original, "_semantic_core_patched", False):
        return

    def save(self, f, format="rdfxml", **kargs):
        kargs = {k: v for k, v in kargs.items() if k in _ALLOWED}
        return original(self, f, format, **kargs)

    save._semantic_core_patched = True
    triplelite.Graph.save = save


_patch_triplelite_save()


Reasoner = Literal["hermit", "pellet"]


class Reasoned:
    """Query interface over a reasoned owlready2 World."""

    def __init__(self, world: owlready2.World, ontology: owlready2.Ontology) -> None:
        self._world = world
        self._ontology = ontology

    @property
    def world(self) -> owlready2.World:
        return self._world

    def types_of(self, iri: str) -> set[str]:
        """All class IRIs an individual belongs to, including inferred superclasses."""
        ind = self._world[iri]
        if ind is None:
            return set()
        return {_iri(c) for c in ind.INDIRECT_is_a if _iri(c) is not None}

    def ancestors_of(self, class_iri: str) -> set[str]:
        """All superclass IRIs of a class, including inferred."""
        cls = self._world[class_iri]
        if cls is None:
            return set()
        return {_iri(c) for c in cls.ancestors() if _iri(c) is not None}

    def materialize(self) -> Graph:
        """Project asserted + inferred type/subclass triples into an rdflib graph.

        owlready2's `ontology.individuals()` returns empty after reasoning
        (apparently the reasoner mutates state in a way that breaks
        iteration). Iterate the underlying world graph for individuals
        with rdf:type instead, then look each up via `world[iri]` to get
        the reasoned `INDIRECT_is_a`.
        """
        world_graph = self._world.as_rdflib_graph()
        result = Graph()
        for t in world_graph:
            result.rdflib_graph.add(t)

        RDF_TYPE = rdflib.RDF.type
        RDFS_SUBCLASS = rdflib.RDFS.subClassOf

        class_iris = set()
        for cls in self._ontology.classes():
            iri = _iri(cls)
            if iri is None:
                continue
            class_iris.add(iri)
            for anc in cls.ancestors():
                anc_iri = _iri(anc)
                if anc_iri is None or anc_iri == iri:
                    continue
                result.rdflib_graph.add(
                    (rdflib.URIRef(iri), RDFS_SUBCLASS, rdflib.URIRef(anc_iri))
                )

        for subject in set(world_graph.subjects(RDF_TYPE, None)):
            s_iri = str(subject)
            if s_iri in class_iris:
                continue
            entity = self._world[s_iri]
            if entity is None or not hasattr(entity, "INDIRECT_is_a"):
                continue
            for c in entity.INDIRECT_is_a:
                c_iri = _iri(c)
                if c_iri is None:
                    continue
                result.rdflib_graph.add(
                    (rdflib.URIRef(s_iri), RDF_TYPE, rdflib.URIRef(c_iri))
                )

        return result


def _iri(obj) -> str | None:
    return getattr(obj, "iri", None)


def reason(
    graph: Graph | rdflib.Graph,
    reasoner: Reasoner = "hermit",
    infer_property_values: bool = True,
) -> Reasoned:
    """Round-trip into owlready2, run reasoner, return a query interface."""
    rdfg = graph.rdflib_graph if isinstance(graph, Graph) else graph

    tmp = tempfile.mkdtemp(prefix="semcore-reason-")
    in_path = Path(tmp) / "in.owl"
    rdfg.serialize(destination=str(in_path), format="xml")

    world = owlready2.World()
    onto = world.get_ontology(in_path.as_uri()).load()

    with onto:
        if reasoner == "hermit":
            owlready2.sync_reasoner_hermit(
                [world], infer_property_values=infer_property_values, debug=0
            )
        elif reasoner == "pellet":
            owlready2.sync_reasoner_pellet(
                [world], infer_property_values=infer_property_values, debug=0
            )
        else:
            raise ValueError(f"unknown reasoner: {reasoner!r}")

    return Reasoned(world, onto)
