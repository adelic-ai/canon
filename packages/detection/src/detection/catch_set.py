"""Catch-set grounding — stage 4 of the detection-treatment pipeline (the keystone).

Stage 3 (the rule lattice, :mod:`detection.rule_lattice`) relates rules by their **clause-sets** — a
*structural* proxy for what they detect. Stage 4 is the **behavioral** ground truth: which rules fire on the
SAME labeled malicious instances. Two rules are **catch-set synonyms** iff their ``caught_on`` sets (the
instance CIDs each fires on) are identical. This is what grounds the lattice edges — *claimed* (structural)
→ *earned* (behavioral) — the load-bearing piece the handoff brief (``catch_set_pivot_brief_2026-06-20``)
names as the keystone.

The catch-set is only as rich as the labeled instances supplied: at **n=1 instance** it degenerates to a
caught/silent split (every catcher fires on the one instance → one behavioral class); it gains resolution
with many instances (the splunk/EVTX per-``T####`` corpora). So ``n_instances`` is reported on every result
and the grounding verdict is read in that light — honest about its own resolution, never a faked richness.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from detection.fidelity import _cid
from detection.rule_ir import compile_rule
from detection.rule_lattice import clause_set, relation, why
from detection.sigma_eval import evaluate_rule, is_evaluable


def rule_catch_sets(rules: list[tuple[str, dict]], instances: list[dict]) -> dict[str, frozenset]:
    """Per rule id, the frozenset of instance CIDs it fires on (its ``caught_on``) — the pure behavioral
    readout, no structure. ``rules``: ``(rule_id, rule_dict)`` pairs; ``instances``: labeled malicious events.
    The instance CID is the same ``_cid`` (canonical-JSON sha2-256) the fidelity evidence uses, so a catch-set
    is reproducible and joins to the fidelity attestations."""
    inst = [(_cid(e), e) for e in instances]
    return {rid: frozenset(cid for cid, e in inst if evaluate_rule(rule, e)["fires"])
            for rid, rule in rules}


def group_by_catch_set(rules: list[tuple[str, dict]], instances: list[dict]) -> dict:
    """Group rules by IDENTICAL ``caught_on`` sets = behavioral catch-set synonymy. The empty catch-set (rules
    silent on every instance here) is reported as ``silent``, **not** a synonymy class — absence of a catch is
    NONE, not a shared class (the carrier discipline applied to grouping). Returns the classes (each ≥1 rule,
    non-empty catch-set), the silent rules, the raw per-rule ``catch_sets``, and a reproducible CID."""
    catch = rule_catch_sets(rules, instances)
    groups: dict[frozenset, list[str]] = defaultdict(list)
    for rid, cs in catch.items():
        groups[cs].append(rid)
    silent = sorted(groups.pop(frozenset(), []))
    classes = [{"caught_on": sorted(cs), "n_caught": len(cs), "rules": sorted(rids)}
               for cs, rids in groups.items()]
    classes.sort(key=lambda c: (-c["n_caught"], c["rules"]))
    return {
        "n_instances": len(instances),
        "n_rules": len(catch),
        "catch_classes": classes,                       # behavioral synonymy classes (co-catch same instances)
        "silent": silent,                               # caught nothing here — NONE, not a class
        "catch_sets": {rid: sorted(cs) for rid, cs in catch.items()},
        "cid": _cid({"n_instances": len(instances),
                     "catch": sorted((rid, sorted(cs)) for rid, cs in catch.items())}),
    }


# behavioral relation of two catch-sets ── the order matters: identical ⊐ intersecting ⊐ disjoint
def _behavioral(ca: frozenset, cb: frozenset) -> str:
    if ca == cb:
        return "co-catch"          # fire on the EXACT same instances — behavioral synonymy
    if ca & cb:
        return "overlap"           # share some, differ on others
    return "disjoint"              # no shared instance


def ground_lattice(rules: list[tuple[str, dict]], instances: list[dict]) -> dict:
    """The keystone comparison (brief step 4): does the **structural** relation (stage-3 lattice) equal the
    **catch** relation (behavioral co-catching)?

    Restricts to **catchers** — rules with a non-empty catch-set — because a silent rule carries no behavioral
    signal on this corpus (its NONE is honest, not a relation). For every unordered pair of catchers it
    cross-tabs the behavioral relation (``co-catch`` / ``overlap`` / ``disjoint``) against the structural
    :func:`detection.rule_lattice.relation` of their positive clause-sets (``exact`` / ``narrower`` /
    ``broader`` / ``related`` / ``none``).

    The result lives in the off-diagonal: a **co-catch pair with structural ``none``** is a behavioral
    synonymy the structure *misses*; a structurally-``exact`` pair that does **not** co-catch is a structural
    *over-claim*. Diagonal agreement (co-catch ↔ structurally-related) is the lattice earning its edges.
    """
    irs: dict[str, object] = {}
    for rid, rule in rules:
        if is_evaluable(rule):
            try:
                irs[rid] = compile_rule(rule)
            except Exception:
                pass                                    # outside the evaluable subset — excluded, recorded below
    catch = rule_catch_sets(rules, instances)
    catchers = sorted(rid for rid, cs in catch.items() if cs and rid in irs)
    csets = {rid: clause_set(irs[rid]) for rid in catchers}

    pairs = []
    crosstab: dict[str, Counter] = defaultdict(Counter)
    for i, a in enumerate(catchers):
        for b in catchers[i + 1:]:
            beh = _behavioral(catch[a], catch[b])
            struct = relation(csets[a], csets[b]) or "none"     # None = disjoint clause-sets / unstructured
            crosstab[beh][struct] += 1
            pairs.append({"a": a, "b": b, "behavioral": beh, "structural": struct,
                          "why": why(csets[a], csets[b])})

    co_catch = [p for p in pairs if p["behavioral"] == "co-catch"]
    missed = [p for p in co_catch if p["structural"] == "none"]   # behavioral synonymy, no structural edge
    return {
        "n_instances": len(instances),
        "n_catchers": len(catchers),
        "catchers": catchers,
        "crosstab": {beh: dict(cols) for beh, cols in crosstab.items()},
        "headline": {
            "co_catch_pairs": len(co_catch),
            "with_structural_edge": len(co_catch) - len(missed),
            "missed_by_structure": [(p["a"], p["b"]) for p in missed],
        },
        "pairs": pairs,
        "cid": _cid({"n_instances": len(instances),
                     "pairs": sorted((p["a"], p["b"], p["behavioral"], p["structural"]) for p in pairs)}),
    }


def otrf_lsass_t1003_grounding(path: str, *, sigma_root=None) -> dict:
    """The thin **n=1** grounding run on the one real labeled case on disk: the comsvcs T1003.001 instance in
    an OTRF LSASS corpus. Gathers every evaluable Sigma rule tagged T1003.001, computes the catch-set grouping
    and the structural-vs-catch comparison against that single labeled positive. n=1 ⇒ the catch-set is a
    caught/silent split; the comparison still answers *are the catchers structurally connected* — the de-risk
    before broadening to multi-instance corpora (splunk/EVTX per-``T####``)."""
    from detection.coverage_space import _comsvcs_positive
    from detection.sigma_panel import SIGMA, gather
    from detection.subgraph import load_sysmon_events

    root = sigma_root or SIGMA
    positive = _comsvcs_positive(load_sysmon_events(path))
    if positive is None:
        return {"error": "no labeled comsvcs T1003.001 positive in corpus", "path": path}
    rules = [(r.get("id", p.name), r) for p, r in gather("T1003.001", root=root)]
    return {
        "technique": "T1003.001",
        "corpus": "OTRF/LSASS_campaign_03",
        "positive_cid": _cid(positive),
        "grouping": group_by_catch_set(rules, [positive]),
        "grounding": ground_lattice(rules, [positive]),
    }
