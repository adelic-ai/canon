"""Phase-B entailment — model-checking over the atom-truth artifact, not sequenced firing.

Phase A (``detection.atoms``) materializes the *comprehensive* atom-truth artifact ``M`` — every distinct
atom evaluated once over the events. Phase B then asks, for each rule/story ``φ``, *does the model satisfy
it* (``M ⊨ φ``). Under a complete assignment that is **model-checking**, not "firing atoms in an order":
the atoms are all settled; you read them and fold booleans. So there is no atom firing order to optimize —
the two levers are:

1. **Pruning** — don't check every story. A *positive-monotone* rule (no negation) can only fire where at
   least one of its atoms is true; on events with none of its atoms true it is provably false, so skip the
   full evaluation. Rules *with* negation can fire on absence (``not filter`` is true when the filter's
   atoms are false), so they are **never pruned** — evaluated on every event. This keeps the engine
   faithful: the prune is a sound necessary condition only where it is sound.
2. **Selectivity short-circuit** — to decide a story cheaply, test its **rarest** atom first (an AND fails
   fast on its least-likely-true clause). The key is the atom's **fire-rate** over the artifact, *not* its
   TTP-spread. Reordering AND-clauses is faithful (AND is commutative).

Faithful by construction: the evaluation reuses the same ``eval_ast`` walker and the artifact's truth as
``eval_ir`` — only the clause *order* (short-circuit) and *which (rule, event) pairs are evaluated* (prune)
change, never the boolean result. ``attest_entailment_agreement`` is the gate.
"""

from __future__ import annotations

from detection.atoms import atom_truth, clause_atom_id, collect_atoms, keyword_atom_id
from detection.condition import eval_ast
from detection.rule_ir import CompiledRule, eval_ir


def has_negation(node: tuple) -> bool:
    """Does the condition AST contain a ``not`` anywhere (so the rule can fire on absence)? Such rules are
    never pruned — the atom-presence prune is unsound for them."""
    kind = node[0]
    if kind == "not":
        return True
    if kind in ("and", "or"):
        return any(has_negation(n) for n in node[1])
    return False


def _rule_atom_ids(ir: CompiledRule) -> set[str]:
    out: set[str] = set()
    for b in ir.blocks:
        if b.kind == "keyword":
            out |= {keyword_atom_id(str(k)) for k in b.keywords}
        else:
            out |= {clause_atom_id(c) for m in b.maps for c in m}
    return out


def selectivity(truth: dict[str, list[bool]]) -> dict[str, float]:
    """Per-atom fire-rate over the artifact (fraction of events the atom is true on). Low = selective =
    test-first for an AND short-circuit. This is the cost key, distinct from TTP-spread (the evidence key)."""
    return {aid: (sum(col) / len(col) if col else 0.0) for aid, col in truth.items()}


def _block_true(block, j: int, truth: dict[str, list[bool]], sel: dict[str, float]) -> bool:
    if block.kind == "keyword":
        return any(truth[keyword_atom_id(str(k))][j] for k in block.keywords)
    for m in block.maps:                                    # OR over maps; AND within a map
        clauses = sorted(m, key=lambda c: sel.get(clause_atom_id(c), 1.0))   # rarest-first short-circuit
        if all(truth[clause_atom_id(c)][j] for c in clauses):
            return True
    return False


def eval_ordered(ir: CompiledRule, j: int, truth: dict[str, list[bool]], sel: dict[str, float]) -> bool:
    """Evaluate ``ir`` on event index ``j`` over the artifact, short-circuiting AND-clauses rarest-first.
    Same boolean as ``eval_ir`` — only the clause order changes."""
    bm = ir.block_map()
    return eval_ast(ir.condition, list(bm),
                    lambda name: name in bm and _block_true(bm[name], j, truth, sel))


def _fires(ir: CompiledRule, j: int, truth, sel, rule_atoms: set[str], negated: bool) -> bool:
    """One (rule, event) decision with the prune: a positive rule with no true atom on ``j`` is False
    without a full evaluation; everything else is fully evaluated."""
    if not negated and not any(truth[a][j] for a in rule_atoms):
        return False
    return eval_ordered(ir, j, truth, sel)


def check_entailment(rules: list[CompiledRule], events: list[dict]) -> dict:
    """Phase B over the comprehensive artifact: which rules are satisfied (``M ⊨ φ``), with pruning +
    selectivity short-circuit. Returns per-rule hit counts and the work the prune saved (full
    (rule, event) evaluations avoided)."""
    atoms = collect_atoms(rules)
    truth = atom_truth(atoms, events)                       # Phase A — comprehensive, the only data pass
    sel = selectivity(truth)
    n = len(events)
    hits: list[int] = []
    evaluated = 0
    for ir in rules:
        ra = _rule_atom_ids(ir)
        neg = has_negation(ir.condition)
        h = 0
        for j in range(n):
            if not neg and not any(truth[a][j] for a in ra):
                continue                                    # pruned — provably False, no full eval
            evaluated += 1
            if eval_ordered(ir, j, truth, sel):
                h += 1
        hits.append(h)
    total = len(rules) * n
    return {
        "hits": hits, "n_rules": len(rules), "n_events": n, "n_atoms": len(atoms),
        "pairs_total": total, "pairs_evaluated": evaluated, "pairs_pruned": total - evaluated,
        "prune_ratio": round(1 - evaluated / total, 3) if total else 0.0,
    }


def attest_entailment_agreement(rules: list[CompiledRule], events: list[dict]) -> dict:
    """Faithfulness gate (mirrors ``attest_factored_agreement`` / ``attest_ir_faithful``): the pruned,
    short-circuited Phase-B decision agrees with ``eval_ir`` on every (rule, event)."""
    atoms = collect_atoms(rules)
    truth = atom_truth(atoms, events)
    sel = selectivity(truth)
    dis = []
    for ir in rules:
        ra = _rule_atom_ids(ir)
        neg = has_negation(ir.condition)
        for j, e in enumerate(events):
            if _fires(ir, j, truth, sel, ra, neg) != eval_ir(ir, e):
                dis.append({"rule": ir.rule_id, "event": j})
    return {"n_rules": len(rules), "n_events": len(events), "checked": len(rules) * len(events),
            "disagreements": dis, "faithful": not dis}
