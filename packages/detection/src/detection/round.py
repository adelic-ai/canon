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
from detection.vocab import NATIVE, require_coherent, vocab_name

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


def _fire_hits(compiled, events: list[dict], *, use_rust: bool) -> tuple[list[int], str]:
    """Per-rule hit count over the events, and which engine fired. The fast path is the native Rust emitter
    (one batched call for all rules × events); rules Rust can't yet handle (re/cidr/gt-lt/windash) fall back to
    the Python ``eval_ir`` — proven-equal for the rest, so the result is identical either way. Returns
    ``(hits, engine)``."""
    if use_rust:
        from detection.rust_emitter import eval_rust, rust_available
        if rust_available():
            results, supported = eval_rust(compiled, events)
            hits = [sum(results[i]) if sup else sum(1 for e in events if eval_ir(compiled[i], e))
                    for i, sup in enumerate(supported)]
            return hits, ("rust+fallback" if not all(supported) else "rust")
    return [sum(1 for e in events if eval_ir(ir, e)) for ir in compiled], "python"


def evaluate_round(events: list[dict], techniques, *, sigma_root: Path = SIGMA, use_rust: bool = True,
                   events_vocab=NATIVE, rules_vocab=NATIVE) -> dict:
    """Fire a whittled round at a log: profile → select (applicable, best-peer) → fire over the events →
    locate (tactic) → rank by severity. Fires through the native Rust emitter when built (``use_rust``), with
    a Python ``eval_ir`` fallback for rust-unsupported clauses — same verdicts, faster path. Returns the
    profile, the selected count, the engine used, and ranked verdicts.

    ``events_vocab``/``rules_vocab`` name the field vocabulary of each side; the round refuses to fire an
    incoherent pair (see ``detection.vocab``). Both default to ``native`` — the identity setting, so the
    existing native-Sigma path is unchanged — and OCSF/bespoke normalization is the opt-in that swaps a side
    onto a shared target vocab."""
    require_coherent(events_vocab, rules_vocab)             # refuse a mismatched pair before firing
    profile = environment_profile(events)
    selected = select_detections(profile, techniques, sigma_root=sigma_root)
    compiled = [compile_rule(s["rule"]) for s in selected]
    hits, engine = _fire_hits(compiled, events, use_rust=use_rust)

    verdicts = []
    for sel, n in zip(selected, hits):
        if n:
            tactic = TECH_TACTIC.get(sel["technique"], "?")
            verdicts.append({"technique": sel["technique"], "tactic": tactic,
                             "rule": sel["name"], "rule_id": sel["rule"].get("id", "?"),
                             "n_hits": n, "severity": _TACTIC_SEVERITY.get(tactic, "medium")})
    verdicts.sort(key=lambda v: (_SEV_RANK.get(v["severity"], 2), v["n_hits"]), reverse=True)
    return {"profile": {"n_events": profile["n_events"], "n_fields": len(profile["fields"])},
            "vocab": {"events": vocab_name(events_vocab), "rules": vocab_name(rules_vocab)},
            "techniques_in_scope": list(techniques), "engine": engine,
            "n_selected": len(selected), "n_fired": len(verdicts), "verdicts": verdicts}
