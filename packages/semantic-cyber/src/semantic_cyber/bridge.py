"""ATT&CK ↔ D3FEND ↔ Sigma bridge.

Folds ``d3fend.derive_counters`` output (per-artifact CounterMatch rows)
into per-defense summaries, combines with ``attack.get_technique``
metadata, and optionally attaches ``sigma.rules_for_technique`` matches —
so a single call answers "what's the full picture (defensive techniques
+ detection rules) for this ATT&CK technique?"

The bridge owns no derivation logic of its own — D3FEND, ATT&CK and
Sigma each keep their own implementations and tests. This module is
the join.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from provenance import Entity, derive, source
from semantic_core.graph import Graph

from . import attack, d3fend, sigma, ukc
from .attack import AttackBundle, Technique
from .sigma import SigmaRule


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
    """Coverage picture for one ATT&CK technique.

    ``defenses`` lists D3FEND defensive techniques (always populated when
    the technique exists in the ATT&CK bundle, possibly empty). ``sigma_rules``
    lists detection rules tagged with the technique — populated only when
    the report came from ``detection_coverage``; ``defensive_coverage`` and
    its fan-out variants leave it as the empty tuple.

    ``provenance`` is a lazy ``provenance.Entity`` recording how this coverage
    was produced. For ``detection_coverage`` the join Activity ``used`` BOTH the
    defensive-coverage lineage AND each sigma rule, so the composition link —
    which defenses and which rules together cover this technique — is preserved
    rather than two flat unlinked lists. ``None`` only on legacy/hand-built
    reports; the coverage functions always populate it.
    """

    technique: Technique
    defenses: tuple[DefenseSummary, ...]
    sigma_rules: tuple[SigmaRule, ...] = field(default=())
    provenance: Entity | None = field(default=None)


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

    # Lineage: the defensive coverage was derived from the D3FEND graph for this
    # technique. The Entity is a record — the (expensive) graph derivation ran
    # eagerly above; evaluating reproduces the coverage content.
    graph_src = source(d3fend_graph, name="d3fend_graph", kind="d3fend_graph")
    technique_src = source(
        attack_id, name=f"attack:{attack_id}", kind="attack_technique", label=attack_id
    )
    prov = derive(
        "defensive_coverage",
        lambda *_inputs, _t=technique, _d=defenses, **_p: CoverageReport(
            technique=_t, defenses=_d
        ),
        (graph_src, technique_src),
        {"attack_id": attack_id},
        kind="coverage",
        label=f"defensive_coverage({attack_id})",
    )
    return CoverageReport(technique=technique, defenses=defenses, provenance=prov)


def detection_coverage(
    d3fend_graph: Graph,
    attack_bundle: AttackBundle,
    sigma_rules: list[SigmaRule],
    attack_id: str,
) -> CoverageReport | None:
    """Return the full coverage picture for one ATT&CK technique.

    Composes ``defensive_coverage`` (D3FEND defensive techniques) with
    ``sigma.rules_for_technique`` (detection rules tagged with the
    technique). Each side keeps its own provenance: ``defenses`` carries
    the artifacts that produced each defensive match, ``sigma_rules``
    carries each rule's full ``SigmaRule`` (including ``path``) so a
    consumer can trace any reported coverage back to the source artifact.

    Returns ``None`` if the technique isn't in the ATT&CK bundle. Empty
    ``defenses`` and/or empty ``sigma_rules`` are valid (technique exists,
    but the corresponding framework has no coverage). Sigma rules are
    sorted by ``(id, title)`` for stable output.
    """
    report = defensive_coverage(d3fend_graph, attack_bundle, attack_id)
    if report is None:
        return None

    matching = sigma.rules_for_technique(sigma_rules, attack_id)
    ordered = tuple(sorted(matching, key=lambda r: (r.id or "", r.title)))

    # The join: this coverage was derived from BOTH the defensive-coverage
    # lineage AND every matching sigma rule. Recording them as a single
    # Activity's used-edges preserves the composition link the audit flagged as
    # lost (defenses and rules were two unlinked lists).
    rule_srcs = tuple(
        source(r, name=f"sigma:{r.id or r.title}", kind="sigma_rule", label=r.id or r.title)
        for r in ordered
    )
    prov = derive(
        "detection_coverage",
        lambda *_inputs, _t=report.technique, _d=report.defenses, _s=ordered, **_p: CoverageReport(
            technique=_t, defenses=_d, sigma_rules=_s
        ),
        (report.provenance, *rule_srcs),
        {"attack_id": attack_id},
        kind="coverage",
        label=f"detection_coverage({attack_id})",
    )
    return CoverageReport(
        technique=report.technique,
        defenses=report.defenses,
        sigma_rules=ordered,
        provenance=prov,
    )


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
