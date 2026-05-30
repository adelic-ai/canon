"""PROV-O emission — the RDF interpreter ([rdf] extra).

``to_prov`` folds the lazy DAG into a W3C PROV-O graph: another interpretation of
the same structure :mod:`provenance.interpret` evaluates. We **import ``prov:``
directly** rather than re-minting PROV terms in a canon namespace — canon wants
*standard* computation provenance and has no reason to diverge (the CASE probe
showed CASE re-implemented PROV-O for domain reasons canon does not share). Only
the genuinely canon-specific predicates (``opName``, ``params``, ``kind``) live in
the canon namespace.

Mapping (op-on-edge categorical = PROV-O):

    Entity            -> prov:Entity
    Activity          -> prov:Activity            (prov:used each input)
    output Entity     -> prov:wasGeneratedBy Activity ; prov:wasDerivedFrom inputs
    recipe            -> prov:Plan via prov:qualifiedAssociation -> prov:Association

This module is the only place rdflib is imported, so the core package stays
dependency-free; it is reachable only when the ``[rdf]`` extra is installed.
"""
from __future__ import annotations

from rdflib import RDF, RDFS, BNode, Graph, Literal, Namespace
from rdflib.namespace import PROV

from provenance.entity import Entity
from provenance.interpret import lineage

# Canon-specific terms only; PROV terms come from rdflib's standard PROV binding.
CANON = Namespace("urn:canon:prov#")
ENT = Namespace("urn:canon:entity:")
ACT = Namespace("urn:canon:activity:")
PLAN = Namespace("urn:canon:plan:")


def to_prov(entity: Entity) -> Graph:
    """Emit the full DAG reachable from ``entity`` as a PROV-O ``rdflib.Graph``.

    Walks :func:`~provenance.interpret.lineage` (no computation) and adds, per
    node: the ``prov:Entity``; for computed nodes the producing ``prov:Activity``
    (``prov:wasGeneratedBy``), its ``prov:used`` inputs and ``prov:wasDerivedFrom``
    shortcuts, and a ``prov:Plan`` (op name + params) attached via a
    ``prov:qualifiedAssociation``. Node URIs are content-addressed by entity /
    activity id, so identical sub-DAGs collapse onto the same RDF nodes.
    """
    g = Graph()
    g.bind("prov", PROV)
    g.bind("canon", CANON)

    for e in lineage(entity):
        e_uri = ENT[e.id]
        g.add((e_uri, RDF.type, PROV.Entity))
        if e.label:
            g.add((e_uri, RDFS.label, Literal(e.label)))
        if e.kind:
            g.add((e_uri, CANON.kind, Literal(e.kind)))

        prod = e.producer
        if prod is None:
            continue  # source: a bare prov:Entity, no generating activity

        a_uri = ACT[prod.id]
        g.add((a_uri, RDF.type, PROV.Activity))
        g.add((e_uri, PROV.wasGeneratedBy, a_uri))
        for u in prod.used:
            u_uri = ENT[u.id]
            g.add((a_uri, PROV.used, u_uri))
            g.add((e_uri, PROV.wasDerivedFrom, u_uri))

        plan_uri = PLAN[prod.id]
        g.add((plan_uri, RDF.type, PROV.Plan))
        g.add((plan_uri, CANON.opName, Literal(prod.op_name)))
        g.add((plan_uri, CANON.params, Literal(repr(prod.params))))

        assoc = BNode()
        g.add((a_uri, PROV.qualifiedAssociation, assoc))
        g.add((assoc, RDF.type, PROV.Association))
        g.add((assoc, PROV.hadPlan, plan_uri))

    return g
