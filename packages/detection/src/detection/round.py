"""Detection round — fire a full, whittled round at a log and rank what comes back.

Not "fire all 3,700 rules." The fidelity work showed most rules don't apply to a given log (wrong channel /
variant). So a round is: **profile** the log's telemetry surface → **select** a whittled, ranked subset (the
FCA-distinct concepts that are *applicable* to the profile, one best-ranked peer each) → **fire** that subset →
**locate** each hit in the kill chain (technique→tactic) → **rank** by severity × the hit. Built on the complete
IR (``rule_ir.compile_rule``/``eval_ir``) — no Rust toolchain; the whittling keeps the fired count small.

What's deliberately *next*, not here: graph-structured firing ORDER (entry-point → frontier-walk via the
killchain priors, D3FEND-scoped) and trajectory assembly — this MVP fires a flat applicable subset and ranks.
And the all-corpus scan (every technique) at enterprise scale needs the fast emitter; this takes a technique
scope and runs on the IR now.

Honest on the profile: it is **inferred** from the log (present fields = the telemetry surface), not declared —
it says what is *observable* here, an upper bound, not what controls are deployed or what the env is exposed to.
"""

from __future__ import annotations

from pathlib import Path

from detection.orchestrator import TECH_TACTIC
from detection.rule_ir import compile_rule, eval_ir
from detection.sigma_eval import is_evaluable
from detection.sigma_panel import SIGMA, gather, signature

# tactic → severity (curated, tactic-based; extensible). Severity ≠ confidence: this is "how bad if real".
_TACTIC_SEVERITY = {
    "credential-access": "high", "privilege-escalation": "high", "lateral-movement": "high",
    "exfiltration": "high", "impact": "high", "command-and-control": "high", "initial-access": "high",
    "execution": "medium", "persistence": "medium", "defense-evasion": "medium", "collection": "medium",
    "discovery": "low", "reconnaissance": "low",
}
_SEV_RANK = {"high": 3, "medium": 2, "low": 1}


def environment_profile(events: list[dict]) -> dict:
    """Infer the telemetry surface of a log: the set of fields present (what is *observable* here). Inferred,
    not declared — an upper bound on observability, not a deployment/exposure profile."""
    fields: set[str] = set()
    for e in events:
        fields.update(e.keys())
    return {"n_events": len(events), "fields": sorted(fields)}


def _required_fields(ir) -> set[str]:
    return {c.field for b in ir.blocks for m in b.maps for c in m}


def _specificity(ir) -> int:
    return sum(len(m) for b in ir.blocks for m in b.maps)   # clause count — more clauses = more specific


def select_detections(profile: dict, techniques, *, sigma_root: Path = SIGMA) -> list[dict]:
    """Whittle to the subset to fire: for each technique, the evaluable rules whose required telemetry is
    present (applicable to the profile), grouped into FCA concepts (same logsource+field-set), keeping the
    **best-ranked peer** per concept. Best-peer here = most specific (clause count) — the "rule with the most
    important features"; a fidelity/clean-catcher ranking slots in where labels exist."""
    present = set(profile["fields"])
    chosen: dict = {}                                        # FCA signature -> best (technique, rule, name, score)
    for tech in techniques:
        for p, r in gather(tech, root=sigma_root):
            if not is_evaluable(r):
                continue
            ir = compile_rule(r)
            req = _required_fields(ir)
            if req and not req <= present:                   # not applicable: required telemetry absent here
                continue
            sig = signature(r)
            score = _specificity(ir)
            if sig not in chosen or score > chosen[sig][3]:
                chosen[sig] = (tech, r, p.name, score)
    return [{"technique": t, "rule": r, "name": name} for (t, r, name, _s) in chosen.values()]


def evaluate_round(events: list[dict], techniques, *, sigma_root: Path = SIGMA) -> dict:
    """Fire a whittled round at a log: profile → select (applicable, best-peer) → fire over the events →
    locate (tactic) → rank by severity. Returns the profile, the selected count, and ranked verdicts (one per
    selected detection that fired, with how many events it hit)."""
    profile = environment_profile(events)
    selected = select_detections(profile, techniques, sigma_root=sigma_root)
    verdicts = []
    for sel in selected:
        ir = compile_rule(sel["rule"])
        n_hits = sum(1 for e in events if eval_ir(ir, e))
        if n_hits:
            tactic = TECH_TACTIC.get(sel["technique"], "?")
            verdicts.append({"technique": sel["technique"], "tactic": tactic,
                             "rule": sel["name"], "rule_id": sel["rule"].get("id", "?"),
                             "n_hits": n_hits, "severity": _TACTIC_SEVERITY.get(tactic, "medium")})
    verdicts.sort(key=lambda v: (_SEV_RANK.get(v["severity"], 2), v["n_hits"]), reverse=True)
    return {"profile": {"n_events": profile["n_events"], "n_fields": len(profile["fields"])},
            "techniques_in_scope": list(techniques),
            "n_selected": len(selected), "n_fired": len(verdicts), "verdicts": verdicts}
