"""d3fend.py — loader + local counter derivation.

Primary tests use a SYNTHETIC mini-ontology that mimics D3FEND's OWL-restriction
shape. Integration test against the real d3fend.ttl is skipped when the file
isn't present.
"""

from __future__ import annotations

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

# Offensive technique uses a credential artifact
d3f:T1558.003 a owl:Class ;
    rdfs:label "Kerberoasting" ;
    rdfs:subClassOf [
        a owl:Restriction ;
        owl:onProperty d3f:may-produce ;
        owl:someValuesFrom d3f:ServiceTicket
    ] .

d3f:ServiceTicket a owl:Class ;
    rdfs:label "Service Ticket" .

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


# Integration test — real D3FEND ontology, skipped if not fetched.
REAL_D3FEND = Path(__file__).resolve().parent.parent / "data" / "d3fend.ttl"


@pytest.mark.skipif(not REAL_D3FEND.exists(), reason="d3fend.ttl not fetched")
def test_real_d3fend_kerberoasting_has_defensive_coverage():
    """T1558.003 must derive a non-trivial defensive coverage set.

    The d3fend.mitre.org API reports 22 defensive techniques for T1558.003
    (per the 2026-05-27 probe pin). Our first-pass local derivation finds
    13 — credible coverage but a known parity gap. Closing it likely
    requires symmetric artifact-subclass expansion on the defensive side,
    additional relation verbs, or OWL-reasoned entailments.
    """
    g = d3fend.load(REAL_D3FEND)
    covering = defensive_techniques_covering(g, "T1558.003")
    assert len(covering) >= 10, f"only {len(covering)} defensive techniques covered T1558.003"
