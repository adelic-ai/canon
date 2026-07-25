"""Orchestrator — drive the registry, guided by the learned kill-chain transition model.

The engine that turns the registry from a list into a system. It does not fire blindly: it fires the
applicable detectors (observability-gated by :func:`detection.run_applicable`), maps each verdict to
its ATT&CK tactic (the attack-path-so-far), then uses the learned ``transitions`` model
(:func:`detection.build_model`) to project the **forward frontier** — which milestone most likely
comes next, and whether we can verify it:

    COVERED            a registered detector for that tactic is applicable to this corpus
    OBSERVABILITY-GAP  a detector exists, but its required data isn't in this corpus
    COVERAGE-GAP       no detector is registered for that tactic at all

The frontier sorted by transition probability is the best-first "where to look next"; the gaps are
the reachable-NONE frontier (moves we have data-backed reason to expect but can't yet verify).

Promoted from experiments: corpus loading is now a parameter (no hardcoded corpora), it consumes the
proper registry + transition model, and emits over canonical verdicts. ``TECH_TACTIC`` is the one bit
of reference data — the tactic each registered technique belongs to (from ATT&CK); deriving it from
the enterprise-attack STIX is the eventual upgrade.
"""

from __future__ import annotations

from collections import defaultdict

from detection.hmm import decode_gated
from detection.killchain import forward_nexts
from detection.registry import REGISTRY, corpus_fields, run_applicable

# technique → ATT&CK tactic for the registered detectors. Reference data (ATT&CK), not demo-specific.
# T1078 (Valid Accounts) is multi-tactic; persistence taken as the dominant reading for an off-hours
# valid-account anomaly. Upgrade path: derive from enterprise-attack.json.
TECH_TACTIC = {
    "T1003.001": "credential-access",   # OS Credential Dumping: LSASS Memory
    "T1110.003": "credential-access",   # Brute Force: Password Spraying
    "T1558.003": "credential-access",   # Kerberoasting
    "T1550.003": "lateral-movement",    # Use Alternate Auth Material: Pass the Ticket
    "T1078": "persistence",             # Valid Accounts (multi-tactic)
    "T1580": "discovery",               # Cloud Infrastructure Discovery (enumeration)
    "T1098": "priv-esc",                # Account Manipulation (IAM privilege grant)
    "T1496": "impact",                  # Resource Hijacking
}

COVERED = "covered"
OBSERVABILITY_GAP = "observability-gap"
COVERAGE_GAP = "coverage-gap"


def _detectors_by_tactic() -> dict:
    out = defaultdict(list)
    for d in REGISTRY:
        out[TECH_TACTIC.get(d.technique)].append(d)
    return out


def orchestrate(corpus_path: str, transitions, *, top_k: int = 4, emissions=None, starts=None) -> dict:
    """Fire applicable detectors over ``corpus_path``, map findings to tactics, then project the
    forward frontier using the learned ``transitions`` model. Returns ``{observed, verdicts, frontier,
    skipped}`` where each frontier row is ``(from_tactic, next_tactic, prob, status, detail)``.

    By default a finding's tactic is the 1:1 ``TECH_TACTIC`` map. Pass ``emissions`` (from
    :func:`detection.emission_model`) **and** ``starts`` to opt into HMM-refined tactics: the hidden
    tactic per finding is Viterbi-decoded, **gated** by corpus coverage (:func:`detection.decode_gated`)
    so an ambiguous in-corpus technique (e.g. ``T1098`` = persistence vs priv-esc) is disambiguated by
    chain context while out-of-corpus techniques fall back to the 1:1 map — additive, never a cloud
    regression."""
    fields = corpus_fields(corpus_path)
    verdicts, skipped = run_applicable(corpus_path, fields=fields)

    if emissions is not None and starts is not None:
        decoded = decode_gated([v.technique for v in verdicts], fallback=TECH_TACTIC,
                               transitions=transitions, starts=starts, emissions=emissions)
    else:
        decoded = [TECH_TACTIC.get(v.technique) for v in verdicts]
    observed: list[str] = []
    for t in decoded:
        if t and t not in observed:
            observed.append(t)

    nexts = forward_nexts(transitions)
    by_tactic = _detectors_by_tactic()
    frontier = []
    for t in observed:
        for nt, p in nexts.get(t, [])[:top_k]:
            dets = by_tactic.get(nt, [])
            applicable = [d.name for d in dets if d.requires <= fields]
            if not dets:
                status, detail = COVERAGE_GAP, "no detector registered for this milestone"
            elif applicable:
                status, detail = COVERED, applicable
            else:
                status, detail = OBSERVABILITY_GAP, [d.name for d in dets]
            frontier.append((t, nt, round(p, 4), status, detail))

    return {"observed": observed, "verdicts": verdicts, "frontier": frontier, "skipped": skipped}
