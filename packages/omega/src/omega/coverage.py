"""ATLAS coverage cartography — the transitive bridge + the five-way classifier (ATLAS-SPEC.md §3.2/§3.3).

The ``atlas`` axis (axes.py) handles *direct* rule -> ATLAS tagging, a per-rule projection. The bridge is
not: it asks, for one ATLAS technique, whether ANY rule in the corpus reaches it — directly, or
transitively through the ATT&CK tag(s) the technique references — so it needs the ingested ATLAS spine as
context. That's what lives here, alongside the honest-silence classification (ATLAS-SPEC.md §4) that is
the actual point of this module: most of the map is silent, and *why* each cell is silent is the finding.

Five statuses, everything an ATLAS technique can be:

  ``covered(direct)``       a rule directly carries this technique's ATLAS tag — the strongest evidence.
  ``covered(bridged)``      no direct tag, but a SIGMA rule carries an ATT&CK tag this technique
                             references — a lead, not a guarantee (§4): the rule detects the ATT&CK
                             technique, which is weak evidence it detects the *AI* manifestation.
  ``uncertain(CAR-coarse)`` the only rule(s) reaching this technique (direct or bridged) are CAR
                             analytics. CAR's ATT&CK coverage is a self-declared field, not corroborated by
                             parsed query logic the way Sigma's clause is (§5) — so this is reported
                             separately from real coverage, not silently folded into either "covered" or
                             "silent".
  ``silent(no-bridge)``     the technique has no ATT&CK reference at all — structurally unreachable by any
                             corpus that only speaks ATT&CK (the AI-native techniques: prompt injection,
                             model evasion, …). Not a gap anyone could fill by writing more Sigma.
  ``silent(uncovered)``     the technique HAS an ATT&CK reference, but no rule (Sigma or CAR) carries the
                             matching tag. A fillable gap — the one status that is actually "someone should
                             write a detection".

Precedence when a technique has evidence at more than one level: direct beats bridged beats CAR-only.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from omega.axes import attributes
from omega.ir import AtlasTechnique, CompiledRule
from omega.skos import Edge, to_turtle as _to_turtle

STATUSES = (
    "covered(direct)",
    "covered(bridged)",
    "uncertain(CAR-coarse)",
    "silent(no-bridge)",
    "silent(uncovered)",
)

# Rulesets whose ATT&CK coverage tag is not corroborated by parsed detection logic (ATLAS-SPEC.md §5).
# Sigma's clause IS parsed (omega reads what the rule actually tests); CAR's is not (query language deferred).
_COARSE_RULESETS = frozenset({"car"})


@dataclass(frozen=True)
class Coverage:
    """One ATLAS technique's coverage verdict. ``rules`` and ``via`` are the provenance ATLAS-SPEC.md §6
    requires: which rule(s) produced the verdict, and — for bridged/uncertain — which ATT&CK tag(s) carried
    it across. Both empty for the two silent statuses (there is nothing to point at)."""

    technique: str
    status: str
    rules: tuple[str, ...]
    via: tuple[str, ...]


def attack_bridge_index(techniques: list[AtlasTechnique]) -> dict[str, list[str]]:
    """``tag:attack.txxxx`` token -> ATLAS technique ids that reference it — the reverse index the bridge
    walks. A token form chosen to compare directly against ``attributes(rule, axes={'attack'})`` output."""
    idx: dict[str, list[str]] = defaultdict(list)
    for t in techniques:
        for ref in t.attack_refs:
            idx[f"tag:{ref}"].append(t.id)
    return idx


def classify(techniques: list[AtlasTechnique], rules: list[CompiledRule]) -> list[Coverage]:
    """The five-way classifier. Deterministic: rule ids are sorted, techniques are visited in input order."""
    direct_by_tech: dict[str, list[str]] = defaultdict(list)
    attack_rules_by_tag: dict[str, list[CompiledRule]] = defaultdict(list)
    for r in rules:
        rid = r.id or ""
        for tok in attributes(r, axes={"atlas"}):
            direct_by_tech[tok.split(":", 1)[1]].append(rid)
        for tok in attributes(r, axes={"attack"}):
            attack_rules_by_tag[tok].append(r)

    out: list[Coverage] = []
    for t in techniques:
        direct = sorted({rid for rid in direct_by_tech.get(t.id, []) if rid})
        if direct:
            out.append(Coverage(t.id, "covered(direct)", tuple(direct), ()))
            continue

        via_tags = [f"tag:{ref}" for ref in t.attack_refs]
        sigma_rules, car_rules, via = [], [], []
        for vt in via_tags:
            hits = attack_rules_by_tag.get(vt, [])
            if not hits:
                continue
            via.append(vt)
            for r in hits:
                ruleset = r.source.ruleset if r.source else None
                (car_rules if ruleset in _COARSE_RULESETS else sigma_rules).append(r)

        if sigma_rules:
            ids = tuple(sorted({r.id for r in sigma_rules if r.id}))
            out.append(Coverage(t.id, "covered(bridged)", ids, tuple(sorted(set(via)))))
        elif car_rules:
            ids = tuple(sorted({r.id for r in car_rules if r.id}))
            out.append(Coverage(t.id, "uncertain(CAR-coarse)", ids, tuple(sorted(set(via)))))
        elif not t.attack_refs:
            out.append(Coverage(t.id, "silent(no-bridge)", (), ()))
        else:
            out.append(Coverage(t.id, "silent(uncovered)", (), ()))
    return out


def summary(coverages: list[Coverage]) -> dict[str, int]:
    """Counts by status, every status key present (even at 0) so the acceptance line always sums to the
    ATLAS technique total (ATLAS-SPEC.md §6) rather than silently omitting an empty bucket."""
    counts = {s: 0 for s in STATUSES}
    for c in coverages:
        counts[c.status] += 1
    return counts


def table(coverages: list[Coverage], techniques: list[AtlasTechnique]) -> list[dict]:
    """The plain coverage table (ATLAS-SPEC.md §3.3): technique -> status -> the rules/tokens that cover
    it, plus the technique name for a human-readable row."""
    names = {t.id: t.name for t in techniques}
    return [
        {"technique": c.technique, "name": names.get(c.technique, ""), "status": c.status,
         "rules": list(c.rules), "via": list(c.via)}
        for c in coverages
    ]


def render(counts: dict[str, int]) -> str:
    """The acceptance line ATLAS-SPEC.md §6 asks for: counts by status, summing to the technique total."""
    total = sum(counts.values())
    parts = " / ".join(f"{s}={counts[s]}" for s in STATUSES)
    return f"atlas coverage — {total} techniques: {parts}"


def to_turtle(coverages: list[Coverage], *, prefix: str = "urn:omega:") -> str:
    """The SKOS graph half of the output (§3.3/§6): one edge per (technique, covering rule) pair — only for
    the two ``covered`` statuses, since ``uncertain``/``silent`` have no confirmed rule<->technique relation
    to assert. ``exactMatch`` for direct tagging (the rule says so), ``relatedMatch`` for bridged (a lead,
    not a guarantee — §4) — reusing skos.py's existing predicate machinery rather than inventing a new one.
    Node names are the raw technique/rule ids (colon-free — ATLAS ids are ``AML.Txxxx``, rule ids are UUIDs
    or corpus-native ids), sharing one flat ``prefix`` namespace exactly as :func:`omega.skos.relate`'s
    rule<->rule edges already do."""
    rel = {"covered(direct)": "exact", "covered(bridged)": "related"}
    edges = [
        Edge(c.technique, rel[c.status], rid, 1.0)
        for c in coverages if c.status in rel
        for rid in c.rules
    ]
    return _to_turtle(edges, prefix=prefix)
