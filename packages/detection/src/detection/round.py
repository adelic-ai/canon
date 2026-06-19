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
from detection.vocab import NATIVE, OCSF, require_coherent, vocab_name

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
                   events_vocab=NATIVE, rules_vocab=NATIVE, adapter=None) -> dict:
    """Fire a whittled round at a log: profile → select (applicable, best-peer) → fire over the events →
    locate (tactic) → rank by severity. Fires through the native Rust emitter when built (``use_rust``), with
    a Python ``eval_ir`` fallback for rust-unsupported clauses — same verdicts, faster path. Returns the
    profile, the selected count, the engine used, and ranked verdicts.

    ``events_vocab``/``rules_vocab`` name the field vocabulary of each side; the round refuses to fire an
    incoherent pair (see ``detection.vocab``). Both default to ``native`` — the identity setting, so the
    existing native-Sigma path is unchanged (the OFF position of the switch). Setting them to ``ocsf`` turns
    normalization ON: the selected rules are rewritten onto OCSF attribute paths and the events normalized to
    OCSF (both via ``adapter``, required in OCSF mode), so a coherent OCSF pair fires — the same engine, vocab
    chosen per run. Selection/whittling stays in native space (telemetry applicability is vocab-independent);
    only the *firing* representation changes.

    In OCSF mode each verdict carries its ``rewrite`` warrant (grade + dropped fields): a rule whose
    load-bearing field has no OCSF home (e.g. ``CallTrace``) fires with ``faithful=False`` and **over-matches**
    relative to native — the honest consequence of normalization, surfaced on the verdict, not hidden. That is
    the demonstration of *when to leave the switch off*."""
    require_coherent(events_vocab, rules_vocab)             # refuse a mismatched pair before firing
    profile = environment_profile(events)                   # native profile — source telemetry, vocab-independent
    selected = select_detections(profile, techniques, sigma_root=sigma_root)
    compiled = [compile_rule(s["rule"]) for s in selected]

    ocsf_mode = vocab_name(rules_vocab) == OCSF
    rewrites = None
    n_unevaluable = 0
    if ocsf_mode:
        if adapter is None:
            raise ValueError("OCSF vocab requires an `adapter` (source→OCSF) to rewrite rules and normalize "
                             "events; pass one (e.g. detection.ocsf_adapter.SYSMON_ADAPTER) or run native.")
        from detection.ocsf_rewrite import rewrite_rule_to_ocsf
        pairs = [(sel, rewrite_rule_to_ocsf(ir, adapter)) for sel, ir in zip(selected, compiled)]
        # A rule with NO field representable in OCSF is UNEVALUABLE under this vocab — skip it (an honest
        # NONE), don't fire it. A rewritten-empty rule would match every event (vacuous AND) — a
        # false-positive flood, the opposite of honest. A *partially* lossy rule (some fields mapped, some
        # dropped) still fires: it over-matches, flagged on the verdict — a bounded, surfaced consequence.
        n_unevaluable = sum(1 for _, rw in pairs if not rw.mapped)
        pairs = [(sel, rw) for sel, rw in pairs if rw.mapped]
        selected = [sel for sel, _ in pairs]
        rewrites = [rw for _, rw in pairs]
        compiled = [rw.rule for rw in rewrites]
        fire_events = adapter.normalize_all(events)
    else:
        fire_events = events
    hits, engine = _fire_hits(compiled, fire_events, use_rust=use_rust)

    verdicts = []
    for i, (sel, n) in enumerate(zip(selected, hits)):
        if n:
            tactic = TECH_TACTIC.get(sel["technique"], "?")
            v = {"technique": sel["technique"], "tactic": tactic,
                 "rule": sel["name"], "rule_id": sel["rule"].get("id", "?"),
                 "n_hits": n, "severity": _TACTIC_SEVERITY.get(tactic, "medium")}
            if ocsf_mode:
                rw = rewrites[i]
                v["rewrite"] = {"grade": rw.grade, "dropped": list(rw.dropped), "faithful": rw.faithful}
            verdicts.append(v)
    verdicts.sort(key=lambda v: (_SEV_RANK.get(v["severity"], 2), v["n_hits"]), reverse=True)
    return {"profile": {"n_events": profile["n_events"], "n_fields": len(profile["fields"])},
            "vocab": {"events": vocab_name(events_vocab), "rules": vocab_name(rules_vocab)},
            "techniques_in_scope": list(techniques), "engine": engine,
            "n_selected": len(selected), "n_fired": len(verdicts),
            "n_unevaluable": n_unevaluable, "verdicts": verdicts}
