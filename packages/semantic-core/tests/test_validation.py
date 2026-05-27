"""validation.py — pySHACL wrapper."""

from __future__ import annotations

from semantic_core.graph import Graph
from semantic_core.validation import ValidationReport, validate


SHAPES = """
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <http://example.org/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

ex:TechniqueShape a sh:NodeShape ;
    sh:targetClass ex:Technique ;
    sh:property [
        sh:path rdfs:label ;
        sh:minCount 1 ;
        sh:datatype <http://www.w3.org/2001/XMLSchema#string> ;
        sh:message "Technique must have an rdfs:label" ;
    ] .
"""

CONFORMING = """
@prefix ex: <http://example.org/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

ex:Kerberoasting a ex:Technique ;
    rdfs:label "Kerberoasting" .
"""

VIOLATING = """
@prefix ex: <http://example.org/> .

ex:UnlabeledTechnique a ex:Technique .
"""


def test_conforming_graph_validates():
    report = validate(Graph().load_turtle(CONFORMING), Graph().load_turtle(SHAPES))
    assert isinstance(report, ValidationReport)
    assert report.conforms is True
    assert report.violations == []


def test_violating_graph_reports_violation():
    report = validate(Graph().load_turtle(VIOLATING), Graph().load_turtle(SHAPES))
    assert report.conforms is False
    assert len(report.violations) >= 1

    v = report.violations[0]
    assert "UnlabeledTechnique" in (v.focus_node or "")
    assert "label" in (v.message or "").lower() or "label" in (v.result_path or "").lower()


def test_accepts_raw_rdflib_graph():
    import rdflib

    data = rdflib.Graph()
    data.parse(data=CONFORMING, format="turtle")
    shapes = rdflib.Graph()
    shapes.parse(data=SHAPES, format="turtle")

    report = validate(data, shapes)
    assert report.conforms is True


def test_report_carries_results_graph():
    report = validate(Graph().load_turtle(VIOLATING), Graph().load_turtle(SHAPES))
    assert report.results_graph is not None
    assert len(report.results_graph) > 0
