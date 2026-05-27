"""attack.py — STIX 2.1 loader + canonical accessors.

Primary tests use a SYNTHETIC mini-bundle with two techniques (T1558 +
T1558.003) linked by a subtechnique-of relationship, plus a tactic.
Integration test against real enterprise-attack.json runs when present.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from semantic_cyber import attack
from semantic_cyber.attack import (
    AttackBundle,
    Technique,
    get_technique,
    load,
    subtechniques,
    tactics_of,
    techniques_for_tactic,
)


SYNTHETIC: dict = {
    "type": "bundle",
    "id": "bundle--test",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1558",
            "name": "Steal or Forge Kerberos Tickets",
            "description": "parent technique",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1558"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_is_subtechnique": False,
            "x_mitre_platforms": ["Windows"],
        },
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
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1110",
            "name": "Brute Force",
            "description": "credential-access via brute force",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_is_subtechnique": False,
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
        },
        {
            "type": "relationship",
            "id": "relationship--t1558-003-sub-of-t1558",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--t1558-003",
            "target_ref": "attack-pattern--t1558",
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--credential-access",
            "name": "Credential Access",
            "x_mitre_shortname": "credential-access",
        },
    ],
}


@pytest.fixture
def bundle(tmp_path) -> AttackBundle:
    p = tmp_path / "synthetic.json"
    p.write_text(json.dumps(SYNTHETIC))
    return load(p)


def test_load_indexes_objects(bundle):
    assert isinstance(bundle, AttackBundle)
    assert "attack-pattern--t1558" in bundle.by_stix_id
    assert bundle.by_attack_id["T1558"]["id"] == "attack-pattern--t1558"


def test_get_technique_returns_typed_record(bundle):
    t = get_technique(bundle, "T1558.003")
    assert isinstance(t, Technique)
    assert t.attack_id == "T1558.003"
    assert t.name == "Kerberoasting"
    assert t.is_subtechnique is True
    assert t.tactics == frozenset({"credential-access"})
    assert t.platforms == ("Windows",)
    assert t.raw["type"] == "attack-pattern"


def test_get_technique_unknown_returns_none(bundle):
    assert get_technique(bundle, "T9999") is None


def test_get_technique_rejects_non_attack_pattern(bundle):
    """The tactic object also has an external/attack ID style entry shape
    in real bundles, but get_technique must only return attack-patterns.
    """
    # Inject a non-attack-pattern object with an attack-id-shaped external_ref
    bundle.by_attack_id["TA0006"] = {
        "type": "x-mitre-tactic",
        "id": "x-mitre-tactic--ta0006",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "TA0006"}
        ],
    }
    assert get_technique(bundle, "TA0006") is None


def test_subtechniques_finds_children(bundle):
    children = subtechniques(bundle, "T1558")
    assert len(children) == 1
    assert children[0].attack_id == "T1558.003"


def test_subtechniques_empty_for_leaf(bundle):
    assert subtechniques(bundle, "T1558.003") == []


def test_subtechniques_empty_for_unknown(bundle):
    assert subtechniques(bundle, "T9999") == []


def test_tactics_of_returns_shortnames(bundle):
    assert tactics_of(bundle, "T1558.003") == {"credential-access"}


def test_tactics_of_unknown_returns_empty(bundle):
    assert tactics_of(bundle, "T9999") == set()


def test_techniques_for_tactic_returns_all_members(bundle):
    techs = techniques_for_tactic(bundle, "credential-access")
    ids = {t.attack_id for t in techs}
    assert ids == {"T1558", "T1558.003", "T1110"}


def test_techniques_for_tactic_unknown_returns_empty(bundle):
    assert techniques_for_tactic(bundle, "no-such-tactic") == []


def test_non_mitre_kill_chain_phases_ignored(tmp_path):
    """Some techniques have kill_chain_phases entries from non-MITRE chains
    (e.g. lockheed-martin-cyber-kill-chain). Those must not appear as tactics.
    """
    b = dict(SYNTHETIC)
    b["objects"] = list(b["objects"]) + [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t9999",
            "name": "Test",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "lockheed-martin-cyber-kill-chain",
                 "phase_name": "reconnaissance"},
                {"kill_chain_name": "mitre-attack", "phase_name": "discovery"},
            ],
        },
    ]
    p = tmp_path / "b.json"
    p.write_text(json.dumps(b))
    bundle = load(p)
    assert tactics_of(bundle, "T9999") == {"discovery"}


# Integration test — real enterprise-attack bundle (fetched via scripts/fetch_attack.py).
REAL_BUNDLE = Path(__file__).resolve().parent.parent / "data" / "enterprise-attack.json"


@pytest.mark.skipif(not REAL_BUNDLE.exists(), reason="enterprise-attack.json not fetched")
def test_real_enterprise_attack_kerberoasting():
    bundle = load(REAL_BUNDLE)
    kerb = get_technique(bundle, "T1558.003")
    assert kerb is not None
    assert kerb.name == "Kerberoasting"
    assert kerb.is_subtechnique is True
    assert "credential-access" in kerb.tactics
    assert "Windows" in kerb.platforms


@pytest.mark.skipif(not REAL_BUNDLE.exists(), reason="enterprise-attack.json not fetched")
def test_real_enterprise_attack_t1558_subtechniques():
    """T1558 has documented sub-techniques: .001 Golden Ticket, .002 Silver
    Ticket, .003 Kerberoasting, .004 AS-REP Roasting, .005 Ccache Files.
    """
    bundle = load(REAL_BUNDLE)
    subs = subtechniques(bundle, "T1558")
    aids = {s.attack_id for s in subs}
    assert {"T1558.001", "T1558.002", "T1558.003", "T1558.004"} <= aids


@pytest.mark.skipif(not REAL_BUNDLE.exists(), reason="enterprise-attack.json not fetched")
def test_real_enterprise_attack_credential_access_membership():
    bundle = load(REAL_BUNDLE)
    cred_access = techniques_for_tactic(bundle, "credential-access")
    aids = {t.attack_id for t in cred_access}
    # Kerberoasting and Brute Force are both credential-access
    assert "T1558.003" in aids
    assert "T1110" in aids
    # Sanity floor — credential-access has dozens of techniques
    assert len(aids) >= 20
