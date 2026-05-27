"""ukc.py — Unified Kill Chain static tables."""

from __future__ import annotations

from semantic_cyber import ukc


def test_eighteen_phases():
    assert len(ukc.UKC_PHASE_TO_ATTACK_TACTICS) == 18
    assert len(ukc.UKC_PHASE_TO_STAGE) == 18


def test_phase_keys_match_across_tables():
    assert (
        ukc.UKC_PHASE_TO_ATTACK_TACTICS.keys()
        == ukc.UKC_PHASE_TO_STAGE.keys()
    )


def test_canonical_phase_order():
    """Insertion order must follow Pols' 1→18 numbering (Reconnaissance
    first, Objectives last) — downstream code relies on this for
    deterministic iteration."""
    phases = list(ukc.UKC_PHASE_TO_STAGE.keys())
    assert phases[0] == "reconnaissance"
    assert phases[-1] == "objectives"
    assert phases[8] == "pivoting"  # first Through phase
    assert phases[14] == "collection"  # first Out phase


def test_three_stages_partition():
    in_phases = [p for p, s in ukc.UKC_PHASE_TO_STAGE.items() if s == "in"]
    through_phases = [p for p, s in ukc.UKC_PHASE_TO_STAGE.items() if s == "through"]
    out_phases = [p for p, s in ukc.UKC_PHASE_TO_STAGE.items() if s == "out"]
    assert len(in_phases) == 8
    assert len(through_phases) == 6
    assert len(out_phases) == 4
    assert len(in_phases) + len(through_phases) + len(out_phases) == 18


def test_stages_constant():
    assert ukc.UKC_STAGES == ("in", "through", "out")


def test_phases_for_stage():
    assert ukc.phases_for_stage("in")[0] == "reconnaissance"
    assert ukc.phases_for_stage("through")[0] == "pivoting"
    assert ukc.phases_for_stage("out") == [
        "collection",
        "exfiltration",
        "impact",
        "objectives",
    ]
    assert ukc.phases_for_stage("nope") == []


def test_ukc_novel_phases_map_to_empty():
    """Four UKC phases have no direct ATT&CK tactic analogue. The mapping
    should be honest about that (empty set, not a forced approximation)."""
    for novel in ("social-engineering", "exploitation", "pivoting", "objectives"):
        assert ukc.UKC_PHASE_TO_ATTACK_TACTICS[novel] == frozenset()


def test_delivery_maps_to_initial_access():
    """UKC's Delivery (a CKC-inherited phase) is ATT&CK's initial-access.
    This is the one phase where the UKC key differs from the ATT&CK
    tactic shortname."""
    assert ukc.UKC_PHASE_TO_ATTACK_TACTICS["delivery"] == frozenset(
        {"initial-access"}
    )


def test_direct_mappings_use_same_shortname():
    """For the 13 UKC phases that aren't Delivery and aren't UKC-novel,
    the UKC phase key equals the ATT&CK tactic shortname."""
    direct = {
        "reconnaissance",
        "resource-development",
        "persistence",
        "defense-evasion",
        "command-and-control",
        "discovery",
        "privilege-escalation",
        "execution",
        "credential-access",
        "lateral-movement",
        "collection",
        "exfiltration",
        "impact",
    }
    for phase in direct:
        assert ukc.UKC_PHASE_TO_ATTACK_TACTICS[phase] == frozenset({phase})
