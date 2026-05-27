"""graph.py — rdflib wrapper."""

from __future__ import annotations

from semantic_core.graph import Graph


TINY_TURTLE = """
@prefix ex: <http://example.org/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

ex:Kerberoasting a ex:Technique ;
    rdfs:label "Kerberoasting" ;
    ex:detectedBy ex:ServiceTicketAnalysis .

ex:ServiceTicketAnalysis a ex:Detection ;
    rdfs:label "Service Ticket Analysis" .
"""


def test_load_turtle_string():
    g = Graph().load_turtle(TINY_TURTLE)
    assert len(g) == 5


def test_chained_load():
    g = Graph().load_turtle(TINY_TURTLE).load_turtle(TINY_TURTLE)
    assert len(g) == 5


def test_sparql_query():
    g = Graph().load_turtle(TINY_TURTLE)
    result = g.query(
        """
        PREFIX ex: <http://example.org/>
        SELECT ?detection WHERE { ex:Kerberoasting ex:detectedBy ?detection }
        """
    )
    rows = list(result)
    assert len(rows) == 1
    assert str(rows[0][0]) == "http://example.org/ServiceTicketAnalysis"


def test_serialize_roundtrip():
    g1 = Graph().load_turtle(TINY_TURTLE)
    serialized = g1.serialize(format="turtle")
    g2 = Graph().load_turtle(serialized)
    assert len(g1) == len(g2)


def test_load_file(tmp_path):
    p = tmp_path / "tiny.ttl"
    p.write_text(TINY_TURTLE)
    g = Graph().load_file(p)
    assert len(g) == 5


def test_rdflib_graph_passthrough():
    import rdflib

    g = Graph().load_turtle(TINY_TURTLE)
    assert isinstance(g.rdflib_graph, rdflib.Graph)


def test_query_on_empty_graph():
    g = Graph()
    result = g.query("SELECT ?s WHERE { ?s ?p ?o }")
    assert list(result) == []
