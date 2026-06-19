"""Atom factoring — read the data once, compose data-free.

The per-TTP coverage model (``design/per_ttp_coverage_layers.md``) splits detection into two phases,
and only one touches the data:

- **Phase A (data-bound, ONCE):** evaluate the *distinct* atom-set over the events → the **atom-truth
  artifact** (``{atom_id: [bool per event]}``). The only pass that reads raw events.
- **Phase B (data-free):** each rule is a fold over the artifact — the events are never re-scanned.

Identical atoms across rules collapse to one node (content-addressed CSE): a clause shared by N rules
is evaluated once, not N times. So **more rules firing ≠ more atom evaluations** — the firing-volume
worry the content-aware signature surfaced dissolves here.

This is the **match-atom** layer — the Sigma clauses / keywords rules are made of, which exist in the
IR today. It is faithful by construction: it reuses the IR's own ``field_matches`` / ``_keyword_hit``
and the same ``eval_ast`` condition walker as :func:`~detection.rule_ir.eval_ir`, so only *where the
clause truth comes from* changes (the cache, not a re-scan). Primitive-level factoring of *statistics*
(sharing ``count``/``sum``/``log`` across entropy/distinct/mean) needs the battery represented as IR
atoms first — that is the follow-on, not this slice.
"""

from __future__ import annotations

import json

from provenance import evidence_digest

from detection.condition import _keyword_hit, eval_ast
from detection.rule_ir import Clause, CompiledRule
from detection.sigma_eval import field_matches


def clause_atom_id(c: Clause) -> str:
    """Content-addressed id of a match-atom ``(field, ops, values)`` — the clause-grain digest. Two
    clauses testing the same field/op/values share an id regardless of which rule they sit in, which
    is what makes the dedup (CSE) automatic."""
    body = ("clause", c.field, list(c.mods), list(c.values))
    return evidence_digest(json.dumps(body, sort_keys=True, separators=(",", ":"), default=list))


def keyword_atom_id(kw: str) -> str:
    """Content-addressed id of a keyword (full-text) atom."""
    return evidence_digest(json.dumps(("keyword", kw), sort_keys=True, separators=(",", ":")))


def collect_atoms(rules: list[CompiledRule]) -> dict[str, tuple]:
    """The distinct atom-set across all rules: ``{atom_id: ("clause", Clause) | ("keyword", str)}``.
    Dedup is by content id, so a clause shared by many rules appears once."""
    atoms: dict[str, tuple] = {}
    for ir in rules:
        for b in ir.blocks:
            if b.kind == "keyword":
                for kw in b.keywords:
                    atoms.setdefault(keyword_atom_id(str(kw)), ("keyword", str(kw)))
            else:
                for m in b.maps:
                    for c in m:
                        atoms.setdefault(clause_atom_id(c), ("clause", c))
    return atoms


def _eval_atom(spec: tuple, event: dict) -> bool:
    kind, payload = spec
    if kind == "clause":
        return field_matches(event.get(payload.field, ""), list(payload.values), set(payload.mods))
    return _keyword_hit(payload, event)


def atom_truth(atoms: dict[str, tuple], events: list[dict]) -> dict[str, list[bool]]:
    """Phase A — evaluate each distinct atom ONCE over every event. ``{atom_id: [bool per event]}``.
    The only data-touching pass; this is the content-addressed atom-truth artifact."""
    return {aid: [_eval_atom(spec, e) for e in events] for aid, spec in atoms.items()}


def _block_truth_cached(block, j: int, truth: dict[str, list[bool]]) -> bool:
    if block.kind == "keyword":
        return any(truth[keyword_atom_id(str(kw))][j] for kw in block.keywords)
    return any(all(truth[clause_atom_id(c)][j] for c in m) for m in block.maps)


def eval_rule_cached(ir: CompiledRule, j: int, truth: dict[str, list[bool]]) -> bool:
    """Phase B — evaluate rule ``ir`` on event index ``j`` using ONLY the artifact (no event access).
    Same condition walker as :func:`~detection.rule_ir.eval_ir`; only the clause/keyword truth is read
    from the cache, so it computes identically."""
    bm = ir.block_map()
    return eval_ast(ir.condition, list(bm),
                    lambda name: name in bm and _block_truth_cached(bm[name], j, truth))


def _instance_count(rules: list[CompiledRule]) -> int:
    """Total clause+keyword *instances* across rules (counting a shared clause once per rule it sits
    in) — the naive per-rule work, the denominator the atom dedup reduces."""
    n = 0
    for ir in rules:
        for b in ir.blocks:
            n += len(b.keywords) if b.kind == "keyword" else sum(len(m) for m in b.maps)
    return n


def fire_factored(rules: list[CompiledRule], events: list[dict]) -> dict:
    """Factored firing: collect distinct atoms → evaluate once (Phase A) → fold each rule over the
    artifact (Phase B). Returns per-rule hit counts and the CSE stats.

    ``n_atoms`` = distinct atoms; ``n_instances`` = total clause/keyword instances across rules (the
    naive per-rule count). ``atom_evals`` = ``n_atoms × |events|`` (factored, no double-counting);
    ``naive_evals`` = ``n_instances × |events|`` (the per-rule upper bound, ignoring short-circuit).
    The dedup factor is ``n_instances / n_atoms``."""
    atoms = collect_atoms(rules)
    truth = atom_truth(atoms, events)
    n = len(events)
    hits = [sum(1 for j in range(n) if eval_rule_cached(ir, j, truth)) for ir in rules]
    n_instances = _instance_count(rules)
    return {
        "hits": hits,
        "n_atoms": len(atoms),
        "n_instances": n_instances,
        "dedup_factor": round(n_instances / len(atoms), 2) if atoms else 0.0,
        "atom_evals": len(atoms) * n,
        "naive_evals": n_instances * n,
    }


def attest_factored_agreement(rules: list[CompiledRule], events: list[dict]) -> dict:
    """Faithfulness gate (mirrors ``attest_ir_faithful`` / ``attest_rust_agreement``): the factored
    path agrees with per-rule :func:`~detection.rule_ir.eval_ir` on every (rule, event). ``faithful``
    iff no disagreement; any disagreement localizes (rule, event)."""
    from detection.rule_ir import eval_ir

    atoms = collect_atoms(rules)
    truth = atom_truth(atoms, events)
    dis = []
    for ir in rules:
        for j, e in enumerate(events):
            if eval_rule_cached(ir, j, truth) != eval_ir(ir, e):
                dis.append({"rule": ir.rule_id, "event": j})
    return {"n_rules": len(rules), "n_events": len(events), "checked": len(rules) * len(events),
            "n_atoms": len(atoms), "disagreements": dis, "faithful": not dis}
