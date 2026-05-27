"""d3fend.py — loader + local counter derivation.

Primary tests use a SYNTHETIC mini-ontology that mimics D3FEND's OWL-restriction
shape: ATT&CK technique classes carry ``d3f:attack-id``; artifact classes are
subclasses of ``d3f:DigitalArtifact``. Integration test against the real
d3fend.ttl is skipped when the file isn't present.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from semantic_core.graph import Graph
from semantic_cyber import d3fend
from semantic_cyber.d3fend import (
    D3F,
    CounterMatch,
    defensive_techniques_covering,
    derive_counters,
)


SYNTHETIC = """
@prefix d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

d3f:DigitalArtifact a owl:Class .

d3f:Credential a owl:Class ;
    rdfs:subClassOf d3f:DigitalArtifact ;
    rdfs:label "Credential" .

d3f:ServiceTicket a owl:Class ;
    rdfs:subClassOf d3f:Credential ;
    rdfs:label "Service Ticket" .

d3f:NetworkTraffic a owl:Class ;
    rdfs:subClassOf d3f:DigitalArtifact ;
    rdfs:label "Network Traffic" .

# Offensive technique uses a credential artifact. attack-id marks it as ATT&CK
# (not a D3FEND grouping class).
d3f:T1558.003 a owl:Class ;
    rdfs:label "Kerberoasting" ;
    d3f:attack-id "T1558.003" ;
    rdfs:subClassOf [
        a owl:Restriction ;
        owl:onProperty d3f:may-produce ;
        owl:someValuesFrom d3f:ServiceTicket
    ] .

# Defensive technique monitors the same artifact
d3f:DefensiveTechnique a owl:Class .

d3f:ServiceTicketAnalysis a owl:Class ;
    rdfs:label "Service Ticket Analysis" ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:analyzes ;
            owl:someValuesFrom d3f:ServiceTicket
        ] .

# Unrelated defensive technique — different artifact
d3f:NetworkTrafficMonitoring a owl:Class ;
    rdfs:label "Network Traffic Monitoring" ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:monitors ;
            owl:someValuesFrom d3f:NetworkTraffic
        ] .
"""


@pytest.fixture
def synthetic_graph() -> Graph:
    return Graph().load_turtle(SYNTHETIC)


def test_load_returns_graph(tmp_path):
    p = tmp_path / "tiny.ttl"
    p.write_text(SYNTHETIC)
    g = d3fend.load(p)
    assert isinstance(g, Graph)
    assert len(g) > 0


def test_derive_counters_finds_shared_artifact_match(synthetic_graph):
    matches = derive_counters(synthetic_graph, "T1558.003")
    assert len(matches) == 1
    m = matches[0]
    assert isinstance(m, CounterMatch)
    assert m.defensive == str(D3F.ServiceTicketAnalysis)
    assert m.offensive == str(D3F["T1558.003"])
    assert m.artifact == str(D3F.ServiceTicket)
    assert m.offensive_relation == str(D3F["may-produce"])
    assert m.defensive_relation == str(D3F.analyzes)
    assert m.defensive_label == "Service Ticket Analysis"
    assert m.artifact_label == "Service Ticket"


def test_derive_counters_excludes_unshared_artifacts(synthetic_graph):
    """NetworkTrafficMonitoring acts on NetworkTraffic, not ServiceTicket."""
    matches = derive_counters(synthetic_graph, "T1558.003")
    defs = {m.defensive for m in matches}
    assert str(D3F.NetworkTrafficMonitoring) not in defs


def test_defensive_techniques_covering_returns_set(synthetic_graph):
    covering = defensive_techniques_covering(synthetic_graph, "T1558.003")
    assert covering == {str(D3F.ServiceTicketAnalysis)}


def test_resolve_technique_accepts_full_iri(synthetic_graph):
    matches = derive_counters(synthetic_graph, str(D3F["T1558.003"]))
    assert len(matches) == 1


def test_unknown_technique_returns_empty(synthetic_graph):
    matches = derive_counters(synthetic_graph, "T9999")
    assert matches == []


def test_class_without_attack_id_returns_empty():
    """Classes lacking d3f:attack-id are D3FEND grouping classes, not ATT&CK
    techniques — the API doesn't consume their restrictions, neither do we.
    """
    g = Graph().load_turtle(
        SYNTHETIC
        + """
d3f:CredentialAccessTechnique a owl:Class ;
    rdfs:subClassOf [
        a owl:Restriction ;
        owl:onProperty d3f:accesses ;
        owl:someValuesFrom d3f:Credential
    ] .
"""
    )
    assert derive_counters(g, "CredentialAccessTechnique") == []


def test_parent_technique_picks_up_subtechnique_restrictions():
    """Querying T1003 picks up restrictions on T1003.001 — the API does this
    via bidirectional subClassOf walk inside the ATT&CK boundary.
    """
    g = Graph().load_turtle(
        """
@prefix d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

d3f:DigitalArtifact a owl:Class .
d3f:LSASSMemory a owl:Class ; rdfs:subClassOf d3f:DigitalArtifact .

d3f:T1003 a owl:Class ; d3f:attack-id "T1003" .

d3f:T1003.001 a owl:Class ;
    rdfs:subClassOf d3f:T1003 ;
    d3f:attack-id "T1003.001" ;
    rdfs:subClassOf [
        a owl:Restriction ;
        owl:onProperty d3f:accesses ;
        owl:someValuesFrom d3f:LSASSMemory
    ] .

d3f:DefensiveTechnique a owl:Class .
d3f:LSASSMemoryAnalysis a owl:Class ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:analyzes ;
            owl:someValuesFrom d3f:LSASSMemory
        ] .
"""
    )
    covering = defensive_techniques_covering(g, "T1003")
    assert covering == {str(D3F.LSASSMemoryAnalysis)}


def test_offensive_artifact_subclass_match_via_ancestor():
    """A defense acting on a SUPERCLASS of an attack-touched artifact still
    catches the attack — ServiceTicket subClassOf Credential, defense
    monitors Credential, attack produces ServiceTicket.
    """
    g = Graph().load_turtle(
        SYNTHETIC
        + """
d3f:CredentialMonitoring a owl:Class ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:monitors ;
            owl:someValuesFrom d3f:Credential
        ] .
"""
    )
    covering = defensive_techniques_covering(g, "T1558.003")
    assert str(D3F.CredentialMonitoring) in covering


def test_non_artifact_restrictions_are_ignored():
    """Restrictions whose someValuesFrom is not a DigitalArtifact subclass
    (e.g. enables Tactic, implemented-by Procedure) must not produce matches.
    """
    g = Graph().load_turtle(
        """
@prefix d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

d3f:DigitalArtifact a owl:Class .
d3f:OffensiveTactic a owl:Class .   # NOT an artifact

d3f:T9999 a owl:Class ;
    d3f:attack-id "T9999" ;
    rdfs:subClassOf [
        a owl:Restriction ;
        owl:onProperty d3f:enables ;
        owl:someValuesFrom d3f:OffensiveTactic
    ] .

d3f:DefensiveTechnique a owl:Class .
d3f:SomeDefense a owl:Class ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:counters ;
            owl:someValuesFrom d3f:OffensiveTactic
        ] .
"""
    )
    assert derive_counters(g, "T9999") == []


# Integration test — real D3FEND ontology, skipped if not fetched.
REAL_D3FEND = Path(__file__).resolve().parent.parent / "data" / "d3fend.ttl"
API_FIXTURE = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "design" / "probes" / "d3fend" / "t1558_003_api_defensive_set.json"
)


@pytest.mark.skipif(not REAL_D3FEND.exists(), reason="d3fend.ttl not fetched")
def test_real_d3fend_kerberoasting_exact_api_parity():
    """Local derivation must reproduce the d3fend.mitre.org API's defensive
    coverage for T1558.003 exactly. The 2026-05-27 API snapshot has 21
    unique defensive techniques; the fixture at
    ``design/probes/d3fend/t1558_003_api_defensive_set.json`` is the
    ground truth.
    """
    g = d3fend.load(REAL_D3FEND)
    covering = defensive_techniques_covering(g, "T1558.003")
    if API_FIXTURE.exists():
        api = json.loads(API_FIXTURE.read_text())
        expected = {dt["iri"] for dt in api["defensive_techniques"]}
        assert covering == expected, (
            f"missing from local: {sorted(expected - covering)}; "
            f"extra in local: {sorted(covering - expected)}"
        )
    else:
        # Fallback: at minimum match the recorded count.
        assert len(covering) == 21
