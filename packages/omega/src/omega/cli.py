"""Stage 6 — the CLI: wire the whole pipeline into one deterministic command.

    python -m omega run --corpus <dir> [--out <dir>] [--aware clause,polarity] [--blind field]
                        [--dimension product] [--min-rules 10]

Ingest a Sigma ruleset, report the over-collapse, and (with ``--out``) write ``figures.json`` +
``lattice.ttl``. The projection is chosen on the command line — nothing privileged — so the same command
answers "same logic?" (default) or "same logic and platform?" (``--aware clause,polarity,logsource``).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from omega.ingest import car
from omega.ingest.sigma import load_ir
from omega.report import analyze, cross_corpus, emit, render, render_cross
from omega.skos import relate


def _axes(spec: str) -> frozenset[str]:
    """Parse a comma-separated axis list — e.g. ``clause,polarity`` — into an axis-set."""
    return frozenset(tok.strip() for tok in spec.split(",") if tok.strip())


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="omega", description="FCA/SKOS rule-sameness over Sigma.")
    sub = p.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="ingest a Sigma ruleset and report the over-collapse")
    run.add_argument("--corpus", required=True, type=Path, help="ruleset directory")
    run.add_argument("--out", type=Path, default=None, help="write figures.json + lattice.ttl here")
    run.add_argument("--aware", type=_axes, default=frozenset({"clause", "polarity"}),
                     help="value-aware projection (default: clause,polarity)")
    run.add_argument("--blind", type=_axes, default=frozenset({"field"}),
                     help="value-blind projection (default: field)")
    run.add_argument("--dimension", default="product", help="logsource dimension to break down by")
    run.add_argument("--min-rules", type=int, default=10, help="omit slices smaller than this")

    bridge = sub.add_parser("bridge", help="ingest two rulesets and show how ATT&CK bridges them")
    bridge.add_argument("--sigma", required=True, type=Path, help="Sigma ruleset directory")
    bridge.add_argument("--car", required=True, type=Path, help="CAR analytics directory")
    bridge.add_argument("--axis", default="attack", help="bridging axis (default: attack)")
    bridge.add_argument("--out", type=Path, default=None, help="write bridge.json here")
    return p


def _run(args: argparse.Namespace) -> int:
    try:
        rules, report = load_ir(args.corpus)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    status = f"ingest: {report.files} files, {report.rules} rules, clean={report.clean}"
    print(status if report.clean else f"{status}, errors={report.errors}")
    if not rules:
        print("no rules parsed", file=sys.stderr)
        return 1

    if args.out:
        rep = emit(rules, args.out, blind=args.blind, aware=args.aware,
                   dimension=args.dimension, min_rules=args.min_rules)
        print(render(rep))
        print(f"\nwrote {args.out}/figures.json and {args.out}/lattice.ttl")
    else:
        edges = relate(rules, axes=args.aware)
        rep = analyze(rules, blind=args.blind, aware=args.aware,
                      dimension=args.dimension, min_rules=args.min_rules, edges=edges)
        print(render(rep))
    return 0


def _bridge(args: argparse.Namespace) -> int:
    try:
        sigma_rules, sig_rep = load_ir(args.sigma)
        car_rules, car_rep = car.load_ir(args.car)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"ingest: sigma {sig_rep.rules} rules, car {car_rep.rules} analytics "
          f"(car deferred={car_rep.deferred})")
    report = cross_corpus(sigma_rules + car_rules, axis=args.axis)
    print(render_cross(report))
    if args.out:
        import json
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))
        print(f"\nwrote {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "run":
        return _run(args)
    if args.cmd == "bridge":
        return _bridge(args)
    return 1
