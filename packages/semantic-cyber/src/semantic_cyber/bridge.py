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

from . import attack, d3fend, ukc
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


def coverage_by_tactic(
    d3fend_graph: Graph,
    attack_bundle: AttackBundle,
    tactic_shortname: str,
) -> list[CoverageReport]:
    """Return CoverageReports for every technique tagged with the tactic.

    Both parent techniques and sub-techniques appear if their
    ``kill_chain_phases`` includes the tactic. Empty list if the tactic
    has no members. Results are sorted by ATT&CK ID for stable output.
    """
    techs = attack.techniques_for_tactic(attack_bundle, tactic_shortname)
    reports = []
    for t in techs:
        report = defensive_coverage(d3fend_graph, attack_bundle, t.attack_id)
        if report is not None:
            reports.append(report)
    reports.sort(key=lambda r: r.technique.attack_id)
    return reports


def coverage_by_ukc_phase(
    d3fend_graph: Graph,
    attack_bundle: AttackBundle,
    ukc_phase: str,
) -> list[CoverageReport]:
    """Return CoverageReports for techniques in a Unified Kill Chain phase.

    Maps the UKC phase to its ATT&CK tactic set (see
    ``semantic_cyber.ukc.UKC_PHASE_TO_ATTACK_TACTICS``) and unions
    ``coverage_by_tactic`` across them. Returns ``[]`` if ``ukc_phase``
    isn't a known UKC phase key, or if it's a UKC-novel phase
    (``social-engineering``, ``exploitation``, ``pivoting``,
    ``objectives``) with no ATT&CK tactic analogue.
    """
    tactics = ukc.UKC_PHASE_TO_ATTACK_TACTICS.get(ukc_phase, frozenset())
    return _fan_coverage_over_tactics(d3fend_graph, attack_bundle, tactics)


def coverage_by_ukc_stage(
    d3fend_graph: Graph,
    attack_bundle: AttackBundle,
    stage: str,
) -> list[CoverageReport]:
    """Return CoverageReports for techniques in a UKC stage (``in``/``through``/``out``).

    Unions the ATT&CK tactics of every UKC phase belonging to the stage,
    then folds ``coverage_by_tactic`` across them. UKC-novel phases
    contribute nothing (their tactic sets are empty).
    """
    tactics: set[str] = set()
    for phase in ukc.phases_for_stage(stage):
        tactics.update(ukc.UKC_PHASE_TO_ATTACK_TACTICS[phase])
    return _fan_coverage_over_tactics(d3fend_graph, attack_bundle, tactics)


def _fan_coverage_over_tactics(
    d3fend_graph: Graph,
    attack_bundle: AttackBundle,
    tactics,
) -> list[CoverageReport]:
    seen: set[str] = set()
    reports: list[CoverageReport] = []
    for tactic in tactics:
        for report in coverage_by_tactic(d3fend_graph, attack_bundle, tactic):
            if report.technique.attack_id in seen:
                continue
            seen.add(report.technique.attack_id)
            reports.append(report)
    reports.sort(key=lambda r: r.technique.attack_id)
    return reports
