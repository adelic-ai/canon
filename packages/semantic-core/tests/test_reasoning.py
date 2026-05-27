"""reasoning.py — owlready2 wrapper.

HermiT runs in a JVM-style native subprocess and adds ~1-2s per test. Kept
to one entailment test to avoid bloating the suite.
"""

from __future__ import annotations

import shutil

import pytest
import rdflib

from semantic_core.graph import Graph
from semantic_core.reasoning import Reasoned, reason


SUBCLASS_ONTOLOGY = """
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix ex: <http://example.org/> .

ex: a owl:Ontology .

ex:Technique a owl:Class .
ex:CredentialAccess a owl:Class ; rdfs:subClassOf ex:Technique .
ex:Kerberoasting a owl:Class ; rdfs:subClassOf ex:CredentialAccess .

ex:T1558_003 a ex:Kerberoasting .
"""


@pytest.mark.skipif(shutil.which("java") is None, reason="HermiT requires Java")
def test_types_of_includes_inferred_superclasses():
    r = reason(Graph().load_turtle(SUBCLASS_ONTOLOGY), reasoner="hermit")
    assert isinstance(r, Reasoned)

    types = r.types_of("http://example.org/T1558_003")
    assert "http://example.org/Kerberoasting" in types
    assert "http://example.org/CredentialAccess" in types
    assert "http://example.org/Technique" in types


@pytest.mark.skipif(shutil.which("java") is None, reason="HermiT requires Java")
def test_ancestors_of_walks_subclass_chain():
    r = reason(Graph().load_turtle(SUBCLASS_ONTOLOGY), reasoner="hermit")
    ancestors = r.ancestors_of("http://example.org/Kerberoasting")
    assert "http://example.org/CredentialAccess" in ancestors
    assert "http://example.org/Technique" in ancestors


@pytest.mark.skipif(shutil.which("java") is None, reason="HermiT requires Java")
def test_materialize_emits_inferred_type_triples():
    r = reason(Graph().load_turtle(SUBCLASS_ONTOLOGY), reasoner="hermit")
    g = r.materialize()

    EX = rdflib.Namespace("http://example.org/")
    type_objects = {str(o) for o in g.rdflib_graph.objects(EX.T1558_003, rdflib.RDF.type)}
    assert str(EX.Kerberoasting) in type_objects
    assert str(EX.CredentialAccess) in type_objects
    assert str(EX.Technique) in type_objects
