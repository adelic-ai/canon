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

from omega.axes import CONTENT, FIELD_SET
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
