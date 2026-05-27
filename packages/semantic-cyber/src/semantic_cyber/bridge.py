"""ATT&CK ↔ D3FEND bridge.

Folds ``d3fend.derive_counters`` output (per-artifact CounterMatch rows)
into per-defense summaries, and combines with ``attack.get_technique``
metadata (name, tactics, sub-technique flag, platforms) so a single call
answers "what's the defensive picture for this ATT&CK technique?"

The bridge owns no derivation logic of its own — both sides keep their
own implementations and tests. This module is the join.
"""

from __future__ import annotations

from dataclasses import dataclass

from semantic_core.graph import Graph

from . import attack, d3fend
from .attack import AttackBundle, Technique


@dataclass(frozen=True)
class DefenseSummary:
    """One defensive technique covering an ATT&CK technique, plus the
    artifacts that produced the join (traceability — which shared
    artifacts caused this defense to be reported as covering)."""

    iri: str
    label: str | None
    via_artifacts: frozenset[str]


@dataclass(frozen=True)
class CoverageReport:
    """Defensive picture for one ATT&CK technique."""

    technique: Technique
    defenses: tuple[DefenseSummary, ...]


def defensive_coverage(
    d3fend_graph: Graph,
    attack_bundle: AttackBundle,
    attack_id: str,
) -> CoverageReport | None:
    """Return defensive coverage + ATT&CK metadata for one technique.

    Returns ``None`` if the technique isn't in the ATT&CK bundle. An empty
    ``defenses`` tuple is a valid result (technique exists, but D3FEND has
    no coverage derived for it).
    """
    technique = attack.get_technique(attack_bundle, attack_id)
    if technique is None:
        return None

    matches = d3fend.derive_counters(d3fend_graph, attack_id)

    # Fold per-artifact matches into per-defense summaries.
    by_defense: dict[str, dict] = {}
    for m in matches:
        entry = by_defense.setdefault(
            m.defensive,
            {"label": m.defensive_label, "artifacts": set()},
        )
        entry["artifacts"].add(m.artifact_label or m.artifact)

    defenses = tuple(
        DefenseSummary(
            iri=iri,
            label=entry["label"],
            via_artifacts=frozenset(entry["artifacts"]),
        )
        for iri, entry in sorted(by_defense.items())
    )

    return CoverageReport(technique=technique, defenses=defenses)
