"""Stage 5 — report + figures: the reproducible over-collapse result over a whole corpus.

Assembles the pipeline (IR → axes → FCA concepts → SKOS lattice) into the numbers the essay cites and emits
them as stable artifacts (``figures.json`` + ``lattice.ttl``), so the claim regenerates rather than being
asserted. The clean, tested replacement for the throwaway ``experiments/fca_skos_*`` scripts.

Everything is parametric in the projection pair (``blind`` vs ``aware``) and in which logsource dimension to
break down by — nothing privileged, per the axes discipline.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from omega.axes import CONTENT, FIELD_SET, attributes
from omega.fca import concepts
from omega.ir import CompiledRule
from omega.skos import counts, relate, to_turtle


def over_collapse(rules: list[CompiledRule], *, blind: frozenset[str] | set[str] = FIELD_SET,
                  aware: frozenset[str] | set[str] = CONTENT) -> dict:
    """The core figure for a rule set: concept counts under a value-BLIND vs a value-AWARE projection, the
    split factor between them, the residue of genuine collapses the aware projection still finds, and the
    biggest single blind concept (the worst over-collapse)."""
    b = concepts(rules, axes=blind)
    a = concepts(rules, axes=aware)
    biggest = max((c.size for c in b.concepts), default=0)
    return {
        "n_rules": len(rules),
        "blind_concepts": b.n_concepts,
        "aware_concepts": a.n_concepts,
        "split_factor": round(a.n_concepts / b.n_concepts, 2) if b.n_concepts else 0.0,
        "aware_residue": len(a.collapsed),          # genuine same-logic collapses left under the fine key
        "biggest_blind_class": biggest,             # most rules the blind key folds into one concept
    }


def by_dimension(rules: list[CompiledRule], dimension: str = "product", *, min_rules: int = 10,
                 blind: frozenset[str] | set[str] = FIELD_SET,
                 aware: frozenset[str] | set[str] = CONTENT) -> list[dict]:
    """Break the over-collapse down by a logsource ``dimension`` (``product`` = platform, ``category`` =
    channel, …) — the generalization check: does the collapse hold in every slice, not just corpus-wide.
    Slices with fewer than ``min_rules`` rules are omitted (too small to read). Deterministic order."""
    groups: dict[str, list[CompiledRule]] = defaultdict(list)
    for r in rules:
        for dim, val in r.logsource:
            if dim == dimension:
                groups[val].append(r)
    rows = [{"value": val, **over_collapse(rs, blind=blind, aware=aware)}
            for val, rs in groups.items() if len(rs) >= min_rules]
    rows.sort(key=lambda x: (-x["n_rules"], x["value"]))
    return rows


def analyze(rules: list[CompiledRule], *, blind: frozenset[str] | set[str] = FIELD_SET,
            aware: frozenset[str] | set[str] = CONTENT, dimension: str = "product", min_rules: int = 10,
            edges=None) -> dict:
    """The full report dict: projections used, corpus-wide over-collapse, the per-dimension breakdown, and —
    if ``edges`` are supplied — the graded-lattice tally. Pure data; :func:`emit` writes it."""
    rows = by_dimension(rules, dimension, min_rules=min_rules, blind=blind, aware=aware)
    report = {
        "n_rules": len(rules),
        "projections": {"blind": sorted(blind), "aware": sorted(aware)},
        "corpus": over_collapse(rules, blind=blind, aware=aware),
        "by_dimension": {"dimension": dimension, "rows": rows},
        "generalizes": all(r["aware_concepts"] > r["blind_concepts"] for r in rows),
    }
    if edges is not None:
        report["lattice"] = counts(edges)
    return report


def emit(rules: list[CompiledRule], out_dir: str | Path, *, blind: frozenset[str] | set[str] = FIELD_SET,
         aware: frozenset[str] | set[str] = CONTENT, dimension: str = "product", min_rules: int = 10) -> dict:
    """Run the report and write the artifacts: ``figures.json`` (the numbers) and ``lattice.ttl`` (the SKOS
    graded graph). Returns the report dict. The lattice is computed once and shared by both."""
    edges = relate(rules, axes=aware)
    report = analyze(rules, blind=blind, aware=aware, dimension=dimension, min_rules=min_rules, edges=edges)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "figures.json").write_text(json.dumps(report, indent=2))
    (out / "lattice.ttl").write_text(to_turtle(edges))
    return report


def cross_corpus(rules: list[CompiledRule], *, axis: str = "attack", sample: int = 6) -> dict:
    """The cross-corpus report: group ``rules`` by their provenance (``source.ruleset``) and measure how well
    a shared ``axis`` BRIDGES the corpora. Consumes the provenance seam — this is what a merged, multi-ruleset
    omega object looks like. ``attack`` is the free bridge (shared vocabulary); a field/clause axis will show
    little overlap (each ruleset's own vocabulary — the mapping seam).

    Returns per-corpus token coverage + what's unique to each, the pairwise overlap, and concrete
    cross-corpus joins (a shared token and the rules from *each* corpus that carry it — the bridge, shown)."""
    by: dict[str, list[CompiledRule]] = defaultdict(list)
    for r in rules:
        by[r.source.ruleset if r.source else "unknown"].append(r)
    corpora = sorted(by)
    toks = {c: set().union(*(attributes(r, axes={axis}) for r in by[c])) if by[c] else set() for c in corpora}

    per = {}
    for c in corpora:
        others = set().union(*(toks[o] for o in corpora if o != c)) if len(corpora) > 1 else set()
        per[c] = {"rules": len(by[c]), "tokens": len(toks[c]), "unique_to_it": len(toks[c] - others)}
    pairwise = {f"{a}~{b}": len(toks[a] & toks[b])
                for i, a in enumerate(corpora) for b in corpora[i + 1:]}
    shared_all = set.intersection(*toks.values()) if len(toks) > 1 else set()

    joins = []
    for tok in sorted(shared_all)[:sample]:
        hit = {c: [r.id for r in by[c] if tok in attributes(r, axes={axis})][:2] for c in corpora}
        joins.append({"token": tok, "rules_by_corpus": hit})

    return {
        "axis": axis,
        "corpora": corpora,
        "per_corpus": per,
        "pairwise_shared": pairwise,
        "shared_by_all": len(shared_all),
        "union": len(set().union(*toks.values())) if toks else 0,
        "sample_joins": joins,
    }


def render_cross(report: dict) -> str:
    """Human-readable cross-corpus bridge report."""
    lines = [f"omega cross-corpus bridge — axis '{report['axis']}' over {report['corpora']}"]
    for c, v in report["per_corpus"].items():
        lines.append(f"  {c:8} rules={v['rules']:5}  {report['axis']}-tokens={v['tokens']:5}  "
                     f"unique-to-it={v['unique_to_it']}")
    lines.append(f"  pairwise shared: {report['pairwise_shared']}   shared-by-all: {report['shared_by_all']}"
                 f"   union: {report['union']}")
    lines.append("  concrete joins (a shared token bridging the corpora):")
    for j in report["sample_joins"]:
        parts = "  ".join(f"{c}={ids}" for c, ids in j["rules_by_corpus"].items())
        lines.append(f"    {j['token']:26} {parts}")
    return "\n".join(lines)


def render(report: dict) -> str:
    """A human-readable text rendering of the report — the console view the old demo scripts printed."""
    c = report["corpus"]
    lines = [
        f"omega over-collapse — {report['n_rules']} rules",
        f"  projections:  blind={report['projections']['blind']}  aware={report['projections']['aware']}",
        f"  corpus:  blind {c['blind_concepts']} concepts  ->  aware {c['aware_concepts']}  "
        f"(split {c['split_factor']}x)   biggest blind class: {c['biggest_blind_class']}  "
        f"aware residue: {c['aware_residue']}",
    ]
    if "lattice" in report:
        lines.append(f"  lattice edges by kind: {report['lattice']}")
    dim = report["by_dimension"]["dimension"]
    lines.append(f"  by {dim} (>= {len(report['by_dimension']['rows'])} slices):")
    lines.append(f"    {'value':16} {'rules':>6} {'blind':>6} {'aware':>6} {'split':>6}  biggest-blind")
    for r in report["by_dimension"]["rows"]:
        lines.append(f"    {r['value']:16} {r['n_rules']:6} {r['blind_concepts']:6} {r['aware_concepts']:6} "
                     f"{r['split_factor']:6}  {r['biggest_blind_class']}")
    lines.append(f"  generalizes (aware > blind in every slice): {report['generalizes']}")
    return "\n".join(lines)
