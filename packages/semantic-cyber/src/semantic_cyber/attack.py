"""ATT&CK STIX 2.1 loader + canonical accessors.

ATT&CK ships as a STIX 2.1 bundle (e.g. ``enterprise-attack.json``). The
file is plain JSON; queries we care about — lookup by ATT&CK ID, sub-technique
enumeration, tactic membership — are dict indexing. We parse directly rather
than pulling in the ``stix2`` library: for these accessors stix2's typed
object model and validation buy nothing the JSON dict doesn't already
provide, and they cost a heavy transitive dependency tree.

STIX 2.1 mapping:

- A technique is an ``attack-pattern`` object. Its ATT&CK ID (``T####`` or
  ``T####.###``) lives in ``external_references[?source_name=='mitre-attack']
  .external_id``. Sub-technique-ness is flagged via ``x_mitre_is_subtechnique``.
- The sub-technique → parent link is a separate ``relationship`` object with
  ``relationship_type == 'subtechnique-of'``, ``source_ref`` (child),
  ``target_ref`` (parent).
- A technique's tactics are listed in ``kill_chain_phases`` as
  ``{kill_chain_name: 'mitre-attack', phase_name: '<tactic-shortname>'}``.
  Tactic shortnames (e.g. ``credential-access``) are the canonical join key
  to ``x-mitre-tactic`` objects (``x_mitre_shortname`` field).

Bundle structure ages slowly — the STIX 2.1 spec hasn't changed shape in
years, and MITRE adds new ``x_mitre_*`` fields rather than restructuring.
A library upgrade isn't load-bearing for what we extract here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique (or sub-technique)."""

    attack_id: str
    stix_id: str
    name: str
    description: str
    tactics: frozenset[str]
    is_subtechnique: bool
    platforms: tuple[str, ...]
    raw: dict


@dataclass
class AttackBundle:
    """Parsed ATT&CK STIX bundle with indices for canonical lookups.

    Indices are built once at load time; accessors are O(1) / O(k) where
    k is the number of children of a parent (sub-techniques) or members
    of a tactic.
    """

    raw: dict
    by_stix_id: dict[str, dict] = field(default_factory=dict)
    by_attack_id: dict[str, dict] = field(default_factory=dict)
    subtech_parent: dict[str, str] = field(default_factory=dict)
    subtechs_of: dict[str, list[str]] = field(default_factory=dict)
    techniques_by_tactic: dict[str, list[str]] = field(default_factory=dict)


def load(path: str | Path) -> AttackBundle:
    """Load an ATT&CK STIX 2.1 bundle and build lookup indices."""
    raw = json.loads(Path(path).read_text())
    return _index(raw)


def get_technique(bundle: AttackBundle, attack_id: str) -> Technique | None:
    """Return the technique with the given ATT&CK ID (e.g. ``"T1558.003"``)."""
    obj = bundle.by_attack_id.get(attack_id)
    if obj is None or obj.get("type") != "attack-pattern":
        return None
    return _to_technique(obj)


def subtechniques(bundle: AttackBundle, parent_attack_id: str) -> list[Technique]:
    """Sub-techniques of the given parent technique. Empty if parent has none."""
    parent = bundle.by_attack_id.get(parent_attack_id)
    if parent is None:
        return []
    children_ids = bundle.subtechs_of.get(parent["id"], [])
    return [_to_technique(bundle.by_stix_id[cid]) for cid in children_ids]


def tactics_of(bundle: AttackBundle, attack_id: str) -> set[str]:
    """Set of tactic shortnames (e.g. ``{'credential-access'}``) for a technique."""
    tech = get_technique(bundle, attack_id)
    return set(tech.tactics) if tech else set()


def techniques_for_tactic(bundle: AttackBundle, shortname: str) -> list[Technique]:
    """All techniques tagged with the given tactic shortname."""
    stix_ids = bundle.techniques_by_tactic.get(shortname, [])
    return [_to_technique(bundle.by_stix_id[sid]) for sid in stix_ids]


def _index(raw: dict) -> AttackBundle:
    bundle = AttackBundle(raw=raw)
    for obj in raw.get("objects", []):
        sid = obj.get("id")
        if not sid:
            continue
        bundle.by_stix_id[sid] = obj
        aid = _attack_id(obj)
        if aid:
            bundle.by_attack_id[aid] = obj
        if obj.get("type") == "attack-pattern":
            for shortname in _tactic_shortnames(obj):
                bundle.techniques_by_tactic.setdefault(shortname, []).append(sid)

    for obj in raw.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "subtechnique-of":
            continue
        child = obj.get("source_ref")
        parent = obj.get("target_ref")
        if child and parent:
            bundle.subtech_parent[child] = parent
            bundle.subtechs_of.setdefault(parent, []).append(child)
    return bundle


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _tactic_shortnames(obj: dict) -> list[str]:
    out = []
    for ph in obj.get("kill_chain_phases", []) or []:
        if ph.get("kill_chain_name") == "mitre-attack":
            name = ph.get("phase_name")
            if name:
                out.append(name)
    return out


def _to_technique(obj: dict) -> Technique:
    return Technique(
        attack_id=_attack_id(obj) or "",
        stix_id=obj["id"],
        name=obj.get("name", ""),
        description=obj.get("description", ""),
        tactics=frozenset(_tactic_shortnames(obj)),
        is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
        platforms=tuple(obj.get("x_mitre_platforms") or ()),
        raw=obj,
    )
