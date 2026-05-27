"""bridge.py — ATT&CK ↔ D3FEND join."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from semantic_core.graph import Graph
from semantic_cyber import attack, d3fend
from semantic_cyber.bridge import (
    CoverageReport,
    DefenseSummary,
    coverage_by_tactic,
    defensive_coverage,
)


# Synthetic fixtures: one ATT&CK technique (T1558.003 Kerberoasting) +
# one D3FEND defense (ServiceTicketAnalysis) that share an artifact.

D3FEND_TTL = """
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

d3f:T1558.003 a owl:Class ;
    rdfs:label "Kerberoasting" ;
    d3f:attack-id "T1558.003" ;
    rdfs:subClassOf [
        a owl:Restriction ;
        owl:onProperty d3f:may-produce ;
        owl:someValuesFrom d3f:ServiceTicket
    ] .

d3f:DefensiveTechnique a owl:Class .
d3f:ServiceTicketAnalysis a owl:Class ;
    rdfs:label "Service Ticket Analysis" ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:analyzes ;
            owl:someValuesFrom d3f:ServiceTicket
        ] .
"""

ATTACK_BUNDLE_DATA = {
    "type": "bundle",
    "id": "bundle--test",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1558-003",
            "name": "Kerberoasting",
            "description": "request service tickets and crack offline",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1558.003"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_is_subtechnique": True,
            "x_mitre_platforms": ["Windows"],
        }
    ],
}


@pytest.fixture
def d3fend_graph() -> Graph:
    return Graph().load_turtle(D3FEND_TTL)


@pytest.fixture
def attack_bundle(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(ATTACK_BUNDLE_DATA))
    return attack.load(p)


def test_defensive_coverage_returns_report(d3fend_graph, attack_bundle):
    report = defensive_coverage(d3fend_graph, attack_bundle, "T1558.003")
    assert isinstance(report, CoverageReport)
    assert report.technique.attack_id == "T1558.003"
    assert report.technique.name == "Kerberoasting"
    assert report.technique.is_subtechnique is True
    assert report.technique.tactics == frozenset({"credential-access"})


def test_defensive_coverage_folds_per_defense(d3fend_graph, attack_bundle):
    report = defensive_coverage(d3fend_graph, attack_bundle, "T1558.003")
    assert len(report.defenses) == 1
    d = report.defenses[0]
    assert isinstance(d, DefenseSummary)
    assert d.iri.endswith("ServiceTicketAnalysis")
    assert d.label == "Service Ticket Analysis"
    assert d.via_artifacts == frozenset({"Service Ticket"})


def test_unknown_technique_returns_none(d3fend_graph, attack_bundle):
    assert defensive_coverage(d3fend_graph, attack_bundle, "T9999") is None


def test_technique_with_no_coverage_returns_empty_defenses(tmp_path):
    """Technique exists in ATT&CK but D3FEND has nothing on it."""
    # ATT&CK has T1190 but D3FEND graph doesn't.
    bundle_data = {
        "type": "bundle",
        "id": "bundle--minimal",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1190",
                "name": "Exploit Public-Facing Application",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            }
        ],
    }
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle_data))
    bundle = attack.load(p)
    g = Graph().load_turtle(D3FEND_TTL)
    report = defensive_coverage(g, bundle, "T1190")
    assert report is not None
    assert report.technique.attack_id == "T1190"
    assert report.defenses == ()


def test_defenses_sorted_by_iri(tmp_path):
    """Multiple defenses must come back in a stable (sorted) order."""
    ttl = D3FEND_TTL + """
d3f:AnotherTicketDefense a owl:Class ;
    rdfs:label "Another Defense" ;
    rdfs:subClassOf d3f:DefensiveTechnique ,
        [
            a owl:Restriction ;
            owl:onProperty d3f:monitors ;
            owl:someValuesFrom d3f:ServiceTicket
        ] .
"""
    g = Graph().load_turtle(ttl)
    p = tmp_path / "b.json"
    p.write_text(json.dumps(ATTACK_BUNDLE_DATA))
    bundle = attack.load(p)
    report = defensive_coverage(g, bundle, "T1558.003")
    iris = [d.iri for d in report.defenses]
    assert iris == sorted(iris)
    assert len(iris) == 2


# Integration: both real datasets present.
REAL_D3FEND = Path(__file__).resolve().parent.parent / "data" / "d3fend.ttl"
REAL_ATTACK = Path(__file__).resolve().parent.parent / "data" / "enterprise-attack.json"


@pytest.mark.skipif(
    not (REAL_D3FEND.exists() and REAL_ATTACK.exists()),
    reason="real data not fetched",
)
def test_real_kerberoasting_bridge_preserves_parity():
    """Bridge over real data must preserve the d3fend-vs-API parity for
    T1558.003: 21 unique defensive techniques.
    """
    g = d3fend.load(REAL_D3FEND)
    bundle = attack.load(REAL_ATTACK)
    report = defensive_coverage(g, bundle, "T1558.003")
    assert report is not None
    assert report.technique.name == "Kerberoasting"
    assert report.technique.is_subtechnique is True
    assert "credential-access" in report.technique.tactics
    assert len(report.defenses) == 21


@pytest.mark.skipif(
    not (REAL_D3FEND.exists() and REAL_ATTACK.exists()),
    reason="real data not fetched",
)
def test_real_t1003_bridge_preserves_parity():
    """T1003 (OS Credential Dumping) — 48 defenses, derived only via
    sub-techniques."""
    g = d3fend.load(REAL_D3FEND)
    bundle = attack.load(REAL_ATTACK)
    report = defensive_coverage(g, bundle, "T1003")
    assert report is not None
    assert report.technique.name == "OS Credential Dumping"
    assert report.technique.is_subtechnique is False
    assert len(report.defenses) == 48


# --- coverage_by_tactic ---


def test_coverage_by_tactic_returns_one_per_technique(d3fend_graph, attack_bundle):
    reports = coverage_by_tactic(d3fend_graph, attack_bundle, "credential-access")
    assert len(reports) == 1
    assert reports[0].technique.attack_id == "T1558.003"
    assert len(reports[0].defenses) == 1


def test_coverage_by_tactic_empty_for_unknown(d3fend_graph, attack_bundle):
    assert coverage_by_tactic(d3fend_graph, attack_bundle, "no-such-tactic") == []


def test_coverage_by_tactic_sorted_by_attack_id(d3fend_graph, tmp_path):
    """Multi-technique bundle: results sorted lexicographically by attack_id."""
    bundle_data = {
        "type": "bundle",
        "id": "b",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1558-003",
                "name": "Kerberoasting",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1558.003"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1110",
                "name": "Brute Force",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1110"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
            },
        ],
    }
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle_data))
    bundle = attack.load(p)
    reports = coverage_by_tactic(d3fend_graph, bundle, "credential-access")
    ids = [r.technique.attack_id for r in reports]
    assert ids == ["T1110", "T1558.003"]


@pytest.mark.skipif(
    not (REAL_D3FEND.exists() and REAL_ATTACK.exists()),
    reason="real data not fetched",
)
def test_real_coverage_by_credential_access():
    """Sanity floor on a real tactic — credential-access has dozens of
    techniques, and well-known ones (T1558.003, T1110) appear with
    expected defense counts.
    """
    g = d3fend.load(REAL_D3FEND)
    bundle = attack.load(REAL_ATTACK)
    reports = coverage_by_tactic(g, bundle, "credential-access")
    assert len(reports) >= 30
    by_id = {r.technique.attack_id: r for r in reports}
    assert len(by_id["T1558.003"].defenses) == 21
    assert len(by_id["T1110"].defenses) == 27
