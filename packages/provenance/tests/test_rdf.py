"""PROV-O emission tests — to_prov folds the DAG to a standard PROV graph.

Structural checks against the emitted rdflib.Graph; no SPARQL needed. Confirms
the op-on-edge -> PROV-O mapping and that content-addressing collapses shared
sub-DAGs onto shared RDF nodes.
"""
import pytest

rdflib = pytest.importorskip("rdflib")
from rdflib import RDF, RDFS, Literal  # noqa: E402
from rdflib.namespace import PROV  # noqa: E402

from provenance import derive, source, to_prov  # noqa: E402
from provenance.rdf import ACT, CANON, ENT, PLAN  # noqa: E402


def test_source_is_bare_entity():
    s = source(7, name="seed")
    g = to_prov(s)
    s_uri = ENT[s.id]
    assert (s_uri, RDF.type, PROV.Entity) in g
    # A source has no producing activity.
    assert (s_uri, PROV.wasGeneratedBy, None) not in g
    assert len(list(g.triples((None, RDF.type, PROV.Activity)))) == 0


def test_computed_entity_emits_activity_and_links():
    a = source(2, name="a")
    b = source(3, name="b")
    s = derive("add", lambda x, y: x + y, (a, b))
    g = to_prov(s)

    s_uri, a_uri, b_uri = ENT[s.id], ENT[a.id], ENT[b.id]
    act_uri = ACT[s.producer.id]

    assert (s_uri, RDF.type, PROV.Entity) in g
    assert (act_uri, RDF.type, PROV.Activity) in g
    assert (s_uri, PROV.wasGeneratedBy, act_uri) in g
    # used + wasDerivedFrom for each input
    assert (act_uri, PROV.used, a_uri) in g
    assert (act_uri, PROV.used, b_uri) in g
    assert (s_uri, PROV.wasDerivedFrom, a_uri) in g
    assert (s_uri, PROV.wasDerivedFrom, b_uri) in g


def test_plan_carries_op_name_and_params():
    x = source(10, name="x")
    s = derive("scale", lambda v, *, factor: v * factor, (x,), {"factor": 3})
    g = to_prov(s)

    act_uri = ACT[s.producer.id]
    plan_uri = PLAN[s.producer.id]
    assoc = g.value(act_uri, PROV.qualifiedAssociation)
    assert assoc is not None
    assert (assoc, RDF.type, PROV.Association) in g
    assert (assoc, PROV.hadPlan, plan_uri) in g
    assert (plan_uri, RDF.type, PROV.Plan) in g
    assert g.value(plan_uri, CANON.opName) == Literal("scale")
    # params are serialized; the factor must appear.
    assert "factor" in str(g.value(plan_uri, CANON.params))


def test_label_and_kind_emitted():
    e = derive("mk", lambda: 1, (), {}, kind="signal", label="raw")
    g = to_prov(e)
    e_uri = ENT[e.id]
    assert (e_uri, RDFS.label, Literal("raw")) in g
    assert (e_uri, CANON.kind, Literal("signal")) in g


def test_one_prov_entity_per_distinct_node():
    a = source(2, name="a")
    b = source(3, name="b")
    s = derive("add", lambda x, y: x + y, (a, b))
    g = to_prov(s)
    entities = set(g.subjects(RDF.type, PROV.Entity))
    assert entities == {ENT[a.id], ENT[b.id], ENT[s.id]}


def test_shared_subdag_collapses_to_one_node():
    seed = source(10, name="seed")
    shared = derive("inc", lambda v: v + 1, (seed,))
    root = derive("sum", lambda p, q: p + q, (shared, shared))
    g = to_prov(root)
    # The diamond's shared node is one prov:Entity / one prov:Activity.
    assert len(list(g.triples((ENT[shared.id], RDF.type, PROV.Entity)))) == 1
    assert len(list(g.triples((ACT[shared.id], RDF.type, PROV.Activity)))) == 1
    # Three distinct entities total: seed, shared, root.
    assert len(set(g.subjects(RDF.type, PROV.Entity))) == 3
