"""Unified Kill Chain — phase definitions and ATT&CK tactic mapping.

The Unified Kill Chain (Pols 2017, white paper v1.3 Feb 2023, GPL v2,
https://www.unifiedkillchain.com/) is a synthesis of Lockheed Martin's
Cyber Kill Chain and MITRE ATT&CK into 18 phases grouped into three
stages: ``In`` (foothold), ``Through`` (propagation), ``Out`` (objectives).

This module exposes the canonical 18 phases as kebab-case keys, the
phase-to-stage grouping, and a phase-to-ATT&CK-tactic mapping derived
from Pols' Table 1 (p. 12). Fourteen UKC phases correspond 1:1 to an
ATT&CK tactic by name; four are UKC novelties with no direct tactic
analogue and map to the empty set:

- ``social-engineering`` — Pols separates it from Exploitation; in ATT&CK
  it surfaces as techniques under ``initial-access`` (e.g. T1566 Phishing).
- ``exploitation`` — ATT&CK has no exploitation tactic; the concept is
  cross-cutting (T1190 in initial-access, T1068 in privilege-escalation).
- ``pivoting`` — UKC novelty; closest ATT&CK techniques live under
  ``lateral-movement`` and ``command-and-control`` (T1090, T1572).
- ``objectives`` — UKC's socio-technical layer; no ATT&CK equivalent.

The mapping is intentionally tactic-level, not technique-level: a
technique-level refinement is possible but requires drawing from Pols'
2017 thesis rather than the white paper, and would couple this table to
ATT&CK technique IDs that change over time.
"""

from __future__ import annotations

UKC_PHASE_TO_ATTACK_TACTICS: dict[str, frozenset[str]] = {
    "reconnaissance":       frozenset({"reconnaissance"}),
    "resource-development": frozenset({"resource-development"}),
    "delivery":             frozenset({"initial-access"}),
    "social-engineering":   frozenset(),
    "exploitation":         frozenset(),
    "persistence":          frozenset({"persistence"}),
    "defense-evasion":      frozenset({"defense-evasion"}),
    "command-and-control":  frozenset({"command-and-control"}),
    "pivoting":             frozenset(),
    "discovery":            frozenset({"discovery"}),
    "privilege-escalation": frozenset({"privilege-escalation"}),
    "execution":            frozenset({"execution"}),
    "credential-access":    frozenset({"credential-access"}),
    "lateral-movement":     frozenset({"lateral-movement"}),
    "collection":           frozenset({"collection"}),
    "exfiltration":         frozenset({"exfiltration"}),
    "impact":               frozenset({"impact"}),
    "objectives":           frozenset(),
}

UKC_PHASE_TO_STAGE: dict[str, str] = {
    "reconnaissance":       "in",
    "resource-development": "in",
    "delivery":             "in",
    "social-engineering":   "in",
    "exploitation":         "in",
    "persistence":          "in",
    "defense-evasion":      "in",
    "command-and-control":  "in",
    "pivoting":             "through",
    "discovery":            "through",
    "privilege-escalation": "through",
    "execution":            "through",
    "credential-access":    "through",
    "lateral-movement":     "through",
    "collection":           "out",
    "exfiltration":         "out",
    "impact":               "out",
    "objectives":           "out",
}

UKC_STAGES: tuple[str, ...] = ("in", "through", "out")


def phases_for_stage(stage: str) -> list[str]:
    """UKC phase keys belonging to a stage, in canonical 1→18 order."""
    return [p for p, s in UKC_PHASE_TO_STAGE.items() if s == stage]
