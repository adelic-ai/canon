"""SHACL validation — the self-falsifying interpreter ([rdf] extra).

``validate`` materializes a derivation as PROV-O (:func:`provenance.rdf.to_prov`)
and runs pySHACL against shapes. This is the generator-validator pairing the
substrate is built on: a derivation ships *with* the shapes that check whether it
is well-formed, so provenance is self-falsifying rather than asserted.

Phase 2 ships generic *structural* shapes (every op-firing must record the plan
that produced it). The CASE-borrowed discipline this anticipates:

* **OWL + SHACL dual-typing** — when canon authors its own op/concept classes
  (Phases 3/5) each is declared as both ``owl:Class`` and ``sh:NodeShape`` so
  semantics and validation live in one artifact. PROV's own classes are defined
  upstream, so the generic shapes here are plain ``sh:NodeShape``\\s over ``prov:``.
* **PASS/XFAIL example pairs** — every shape ships a positive instance that must
  conform and a negative that must fail; see ``tests/test_shacl.py``.
"""
from __future__ import annotations

from dataclasses import dataclass

import pyshacl
from rdflib import Graph

from provenance.entity import Entity
from provenance.rdf import to_prov

# Generic well-formedness: a derivation is auditable only if every op-firing
# records the recipe that produced it. An Activity without a qualifiedAssociation
# (-> Plan), or an Association without a Plan, is malformed provenance.
_WELL_FORMED_TTL = """
@prefix sh:   <http://www.w3.org/ns/shacl#> .
@prefix prov: <http://www.w3.org/ns/prov#> .

[] a sh:NodeShape ;
   sh:targetClass prov:Activity ;
   sh:property [
       sh:path prov:qualifiedAssociation ;
       sh:minCount 1 ;
       sh:message "every prov:Activity must record a qualifiedAssociation (-> Plan)"
   ] .

[] a sh:NodeShape ;
   sh:targetClass prov:Association ;
   sh:property [
       sh:path prov:hadPlan ;
       sh:minCount 1 ;
       sh:message "every prov:Association must reference a prov:Plan"
   ] .
"""


@dataclass(frozen=True)
class ValidationReport:
    """Outcome of a SHACL run: did it conform, the human text, the results graph."""

    conforms: bool
    text: str
    results: Graph


def well_formed_shapes() -> Graph:
    """The generic structural shapes shipped by this package, as a fresh Graph."""
    g = Graph()
    g.parse(data=_WELL_FORMED_TTL, format="turtle")
    return g


def _as_graph(shapes: "Graph | str") -> Graph:
    if isinstance(shapes, Graph):
        return shapes
    g = Graph()
    g.parse(data=shapes, format="turtle")
    return g


def validate_graph(data: Graph, shapes: "Graph | str | None" = None) -> ValidationReport:
    """Run pySHACL over an already-materialized data graph.

    ``shapes`` may be an ``rdflib.Graph`` or a turtle string; if omitted, the
    package's :func:`well_formed_shapes` are used.
    """
    shapes_graph = _as_graph(shapes) if shapes is not None else well_formed_shapes()
    conforms, results_graph, text = pyshacl.validate(
        data,
        shacl_graph=shapes_graph,
        inference="none",
        advanced=True,  # enable SHACL Advanced Features (SPARQL targets + sh:sparql) for domain shapes
    )
    return ValidationReport(conforms=conforms, text=text, results=results_graph)


def validate(entity: Entity, shapes: "Graph | str | None" = None) -> ValidationReport:
    """Materialize ``entity`` as PROV-O and SHACL-validate it.

    The self-falsifying check: ``validate(d).conforms`` answers "is this
    derivation well-formed provenance?" without trusting any assertion about it.
    """
    return validate_graph(to_prov(entity), shapes)
