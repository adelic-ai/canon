"""sigma.py — Sigma rule loader + ATT&CK tag extraction."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from semantic_cyber import sigma
from semantic_cyber.sigma import (
    SigmaRule,
    load_rule,
    load_rules,
    rules_for_tactic,
    rules_for_technique,
)


# A real-shaped Sigma rule (Kerberoasting initial query — SigmaHQ
# d04ae2b8-ad54-4de0-bd87-4bc1da66aa59), trimmed.
KERBEROAST_RULE = dedent("""
    title: Kerberoasting Activity - Initial Query
    id: d04ae2b8-ad54-4de0-bd87-4bc1da66aa59
    status: test
    description: Collect data for kerberoasting analysis.
    tags:
        - attack.credential-access
        - attack.t1558.003
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4769
        condition: selection
    level: medium
""").lstrip()


@pytest.fixture
def kerberoast_path(tmp_path):
    p = tmp_path / "kerberoast.yml"
    p.write_text(KERBEROAST_RULE)
    return p


def test_load_rule_parses_required_fields(kerberoast_path):
    rule = load_rule(kerberoast_path)
    assert isinstance(rule, SigmaRule)
    assert rule.id == "d04ae2b8-ad54-4de0-bd87-4bc1da66aa59"
    assert rule.title == "Kerberoasting Activity - Initial Query"
    assert rule.status == "test"
    assert rule.level == "medium"
    assert rule.logsource == {"product": "windows", "service": "security"}


def test_load_rule_extracts_technique_and_tactic(kerberoast_path):
    rule = load_rule(kerberoast_path)
    assert rule.attack_techniques == frozenset({"T1558.003"})
    assert rule.attack_tactics == frozenset({"credential-access"})
    assert rule.raw_tags == ("attack.credential-access", "attack.t1558.003")


def test_load_rule_preserves_raw_dict(kerberoast_path):
    rule = load_rule(kerberoast_path)
    assert rule.raw["detection"]["selection"]["EventID"] == 4769
    assert rule.raw["detection"]["condition"] == "selection"


def test_technique_id_normalized_to_uppercase(tmp_path):
    """Sigma tags use lowercase 't1558.003'; canonical ATT&CK is 'T1558.003'."""
    p = tmp_path / "r.yml"
    p.write_text(dedent("""
        title: t
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
        tags: [attack.T1110, attack.t1003.001]
    """).lstrip())
    rule = load_rule(p)
    assert rule.attack_techniques == frozenset({"T1110", "T1003.001"})


def test_attack_id_tags_ignored(tmp_path):
    """ATT&CK ID-shaped tags (group, software, data-source, mitigation,
    campaign, STIX tactic) share the namespace-tag shape but aren't
    tactics — must not leak into attack_tactics."""
    p = tmp_path / "r.yml"
    p.write_text(dedent("""
        title: t
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
        tags:
            - attack.g0007
            - attack.s0001
            - attack.ds0005
            - attack.m1041
            - attack.c0001
            - attack.ta0006
            - attack.persistence
    """).lstrip())
    rule = load_rule(p)
    assert rule.attack_tactics == frozenset({"persistence"})
    assert rule.attack_techniques == frozenset()


def test_sigmahq_house_tactic_names_captured(tmp_path):
    """SigmaHQ uses attack.stealth in place of attack.defense-evasion and
    attack.defense-impairment for T1562 Impair Defenses. These don't
    match ATT&CK enterprise tactic shortnames but are kebab-case under
    the attack namespace — the parser captures them honestly."""
    p = tmp_path / "r.yml"
    p.write_text(dedent("""
        title: t
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
        tags:
            - attack.stealth
            - attack.defense-impairment
    """).lstrip())
    rule = load_rule(p)
    assert rule.attack_tactics == frozenset({"stealth", "defense-impairment"})


def test_non_attack_tags_left_in_raw_only(tmp_path):
    """CVE / other-namespace tags are preserved in raw_tags but don't
    populate the ATT&CK-specific fields."""
    p = tmp_path / "r.yml"
    p.write_text(dedent("""
        title: t
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
        tags:
            - cve.2021-44228
            - misp.threat-level
            - attack.t1190
    """).lstrip())
    rule = load_rule(p)
    assert rule.attack_techniques == frozenset({"T1190"})
    assert rule.attack_tactics == frozenset()
    assert "cve.2021-44228" in rule.raw_tags
    assert "misp.threat-level" in rule.raw_tags


def test_missing_optional_fields_default_safely(tmp_path):
    """A spec-minimal rule (title + logsource + detection) loads cleanly."""
    p = tmp_path / "r.yml"
    p.write_text(dedent("""
        title: minimal
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
    """).lstrip())
    rule = load_rule(p)
    assert rule.id is None
    assert rule.status is None
    assert rule.level is None
    assert rule.description == ""
    assert rule.attack_techniques == frozenset()
    assert rule.attack_tactics == frozenset()
    assert rule.raw_tags == ()


def test_load_rule_rejects_non_mapping(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="not a YAML mapping"):
        load_rule(p)


def test_load_rules_skips_non_rule_yaml(tmp_path):
    """SigmaHQ ships configs + templates alongside rules; load_rules
    must skip files without a title rather than raising."""
    (tmp_path / "good.yml").write_text(KERBEROAST_RULE)
    (tmp_path / "config.yml").write_text("foo:\n  bar: 1\n")
    (tmp_path / "broken.yml").write_text("title: t\n  bad: [unclosed\n")
    (tmp_path / "list.yml").write_text("- a\n- b\n")
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].title == "Kerberoasting Activity - Initial Query"


def test_load_rules_walks_recursively(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").mkdir()
    (tmp_path / "a" / "r1.yml").write_text(KERBEROAST_RULE)
    (tmp_path / "a" / "b" / "r2.yml").write_text(KERBEROAST_RULE)
    assert len(load_rules(tmp_path)) == 2


def test_load_rules_returns_stable_order(tmp_path):
    """Two rules with deterministic file names — order must be stable
    (sorted) so downstream parity checks are reproducible."""
    (tmp_path / "z.yml").write_text(KERBEROAST_RULE)
    (tmp_path / "a.yml").write_text(KERBEROAST_RULE)
    paths = [r.path.name for r in load_rules(tmp_path)]
    assert paths == ["a.yml", "z.yml"]


def test_rules_for_technique(tmp_path):
    (tmp_path / "k.yml").write_text(KERBEROAST_RULE)
    (tmp_path / "other.yml").write_text(dedent("""
        title: other
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
        tags: [attack.t1110]
    """).lstrip())
    rules = load_rules(tmp_path)
    assert len(rules_for_technique(rules, "T1558.003")) == 1
    assert len(rules_for_technique(rules, "T1110")) == 1
    assert rules_for_technique(rules, "T9999") == []


def test_rules_for_tactic(tmp_path):
    (tmp_path / "k.yml").write_text(KERBEROAST_RULE)
    (tmp_path / "other.yml").write_text(dedent("""
        title: other
        logsource: {product: x}
        detection: {sel: {EventID: 1}, condition: sel}
        tags: [attack.persistence]
    """).lstrip())
    rules = load_rules(tmp_path)
    assert len(rules_for_tactic(rules, "credential-access")) == 1
    assert len(rules_for_tactic(rules, "persistence")) == 1
    assert rules_for_tactic(rules, "no-such-tactic") == []


# --- Real-data integration (skipped until scripts/fetch_sigma.py is run) ---

REAL_SIGMA = Path(__file__).resolve().parent.parent / "data" / "sigma-rules"


@pytest.mark.skipif(
    not REAL_SIGMA.exists(),
    reason="SigmaHQ rules not fetched — run scripts/fetch_sigma.py",
)
def test_real_load_returns_thousands_of_rules():
    """Sanity floor: SigmaHQ ships 3000+ rules across the six rule dirs."""
    rules = load_rules(REAL_SIGMA)
    assert len(rules) >= 3000


@pytest.mark.skipif(
    not REAL_SIGMA.exists(),
    reason="SigmaHQ rules not fetched — run scripts/fetch_sigma.py",
)
def test_real_kerberoasting_has_rules():
    """T1558.003 is well-covered in SigmaHQ — at least 10 Windows-security
    rules tagged with it (corpus observed: 17 at fetch time)."""
    rules = load_rules(REAL_SIGMA)
    hits = rules_for_technique(rules, "T1558.003")
    assert len(hits) >= 10
    products = {r.logsource.get("product") for r in hits}
    assert "windows" in products


@pytest.mark.skipif(
    not REAL_SIGMA.exists(),
    reason="SigmaHQ rules not fetched — run scripts/fetch_sigma.py",
)
def test_real_credential_access_tactic_has_many_rules():
    rules = load_rules(REAL_SIGMA)
    hits = rules_for_tactic(rules, "credential-access")
    assert len(hits) >= 300


@pytest.mark.skipif(
    not REAL_SIGMA.exists(),
    reason="SigmaHQ rules not fetched — run scripts/fetch_sigma.py",
)
def test_real_no_attack_id_leaks_into_tactics():
    """Regression for the ds0005 leak: no extracted 'tactic' should match
    any ATT&CK ID format (G/S/M/C/DS/TA prefixed numeric)."""
    import re

    pattern = re.compile(r"^(g|s|m|c|ds|ta)\d+$")
    rules = load_rules(REAL_SIGMA)
    leaks: set[str] = set()
    for r in rules:
        for t in r.attack_tactics:
            if pattern.match(t):
                leaks.add(t)
    assert leaks == set(), f"ATT&CK IDs leaked into attack_tactics: {leaks}"


@pytest.mark.skipif(
    not REAL_SIGMA.exists(),
    reason="SigmaHQ rules not fetched — run scripts/fetch_sigma.py",
)
def test_real_sigmahq_uses_stealth_not_defense_evasion():
    """Locks in the corpus observation: SigmaHQ tags ~1000+ rules with
    attack.stealth and zero rules with attack.defense-evasion. Future-self
    check — if MITRE/SigmaHQ migrate, this test will flag it."""
    rules = load_rules(REAL_SIGMA)
    stealth = rules_for_tactic(rules, "stealth")
    defense_evasion = rules_for_tactic(rules, "defense-evasion")
    assert len(stealth) >= 500
    assert len(defense_evasion) == 0
