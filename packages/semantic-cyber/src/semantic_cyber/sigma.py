"""Sigma detection-rule loader + ATT&CK technique/tactic accessors.

Sigma rules (https://github.com/SigmaHQ/sigma-specification, spec v2.1.0,
Sep 2025) are YAML files describing platform-agnostic detection logic.
Rules carry ATT&CK tags in the ``tags`` field under the ``attack.``
namespace — these are the join key to MITRE ATT&CK.

We parse the YAML directly with PyYAML and surface a minimal typed
``SigmaRule`` for the fields canon needs (id, title, status, level,
logsource, normalized ATT&CK technique/tactic sets), keeping the full
dict at ``.raw`` so consumers that want detection logic, modifiers, or
custom fields can reach in.

Tag conventions (per the spec's tags appendix and observed in SigmaHQ):
- ``attack.t1558.003`` → technique T1558.003
- ``attack.t1110``     → technique T1110
- ``attack.credential-access`` → tactic ``credential-access``
- ``attack.g0007`` / ``attack.s0001`` / ``attack.ds0005`` / ``attack.m1041``
  / ``attack.c0001`` → group / software / data-source / mitigation /
  campaign IDs (ignored here; preserved in ``raw_tags``)

ATT&CK technique IDs in Sigma tags are lowercase; we normalize to
canonical uppercase (``T1558.003``) on extraction so the join key
matches ``attack.Technique.attack_id``.

**SigmaHQ taxonomy divergence:** SigmaHQ tags rules with two tactic-shaped
names that aren't ATT&CK tactic shortnames — ``attack.stealth`` (used in
place of ``defense-evasion``, ~1100 rules) and ``attack.defense-impairment``
(roughly T1562 Impair Defenses, ~400 rules). These appear in
``attack_tactics`` because the parser extracts what's there. ``defense-evasion``
itself is absent from the SigmaHQ corpus. Callers that want strict ATT&CK
tactic alignment should filter ``attack_tactics`` against the official
ATT&CK enterprise tactic shortnames.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


_TECHNIQUE_TAG = re.compile(r"^attack\.t(\d+(?:\.\d+)?)$", re.IGNORECASE)
_NAMESPACE_TAG = re.compile(r"^attack\.([a-z][a-z0-9_-]*)$")
# ATT&CK ID formats that share the namespace-tag shape but aren't tactics:
# G#### (group), S#### (software), DS#### (data source), M#### (mitigation),
# C#### (campaign), TA#### (STIX tactic ID).
_ATTACK_ID = re.compile(r"^(g|s|m|c|ds|ta)\d+$")


@dataclass(frozen=True)
class SigmaRule:
    """One Sigma detection rule.

    Fields follow the v2.1.0 spec: ``id`` (UUID, optional), ``title``
    (required), ``logsource`` and ``detection`` (required), all others
    optional. ``attack_techniques`` and ``attack_tactics`` are extracted
    from ``raw_tags`` for join convenience.
    """

    id: str | None
    title: str
    description: str
    status: str | None
    level: str | None
    logsource: dict
    raw_tags: tuple[str, ...]
    attack_techniques: frozenset[str]
    attack_tactics: frozenset[str]
    path: Path | None
    raw: dict


def load_rule(path: str | Path) -> SigmaRule:
    """Parse one Sigma YAML file. Raises on malformed YAML or missing title."""
    p = Path(path)
    data = yaml.safe_load(p.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{p}: not a YAML mapping")
    return _to_rule(data, p)


def load_rules(directory: str | Path) -> list[SigmaRule]:
    """Walk a directory tree recursively, returning every parseable rule.

    Files that aren't valid YAML, aren't a mapping, or lack a ``title``
    are skipped silently — the SigmaHQ repo ships non-rule YAML alongside
    rules (configs, templates, correlation drafts). Use ``load_rule`` for
    a single path if you want errors to surface.
    """
    rules: list[SigmaRule] = []
    for p in sorted(Path(directory).rglob("*.yml")):
        try:
            data = yaml.safe_load(p.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "title" not in data:
            continue
        rules.append(_to_rule(data, p))
    return rules


def rules_for_technique(rules: list[SigmaRule], attack_id: str) -> list[SigmaRule]:
    """Sigma rules tagged with the given ATT&CK technique (e.g. ``"T1558.003"``)."""
    return [r for r in rules if attack_id in r.attack_techniques]


def rules_for_tactic(rules: list[SigmaRule], tactic_shortname: str) -> list[SigmaRule]:
    """Sigma rules tagged with the given ATT&CK tactic shortname."""
    return [r for r in rules if tactic_shortname in r.attack_tactics]


def _to_rule(data: dict, path: Path | None) -> SigmaRule:
    raw_tags = tuple(data.get("tags") or ())
    techniques: set[str] = set()
    tactics: set[str] = set()
    for tag in raw_tags:
        if not isinstance(tag, str):
            continue
        m = _TECHNIQUE_TAG.match(tag)
        if m:
            techniques.add("T" + m.group(1).upper())
            continue
        m = _NAMESPACE_TAG.match(tag)
        if m and not _ATTACK_ID.match(m.group(1)):
            tactics.add(m.group(1))
    return SigmaRule(
        id=data.get("id"),
        title=data.get("title", ""),
        description=data.get("description") or "",
        status=data.get("status"),
        level=data.get("level"),
        logsource=data.get("logsource") or {},
        raw_tags=raw_tags,
        attack_techniques=frozenset(techniques),
        attack_tactics=frozenset(tactics),
        path=path,
        raw=data,
    )
