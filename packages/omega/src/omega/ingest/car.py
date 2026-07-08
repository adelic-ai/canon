"""The CAR adapter — MITRE Cyber Analytics Repository, omega's second ingest front-end (adapter #2).

CAR is structurally unlike Sigma, and that is the point of a second adapter: it is not a single-language
ruleset but a **container of detection *intents***, each with 0–N concrete ``implementations`` in *other*
query languages (Splunk SPL, EQL, LogPoint, pseudocode, even Sigma). So a CAR analytic does not fit
``CompiledRule``'s one-rule-one-logic shape at the atom level without parsing those query languages — the
same "needs a query parser" cost omega defers for SPL/EQL.

**v1 (this module): the free, structured axes only** — no query parsing:
  * ``coverage``               → ATT&CK tags (technique + subtechniques), the SHARED cross-ruleset axis
  * ``platforms``              → logsource ``product`` tags
  * ``data_model_references``  → coarse, value-blind field atoms (CAR's OWN vocabulary — ``exe``, not
                                 Sigma's ``Image``; so field-level alignment across corpora needs a mapping,
                                 deferred, while ATT&CK bridges for free)

The atom-level query logic (SPL/EQL/pseudocode) is counted in the report as
``deferred["unparsed-implementations"]`` — seen, honestly not analysed, not silently dropped. Every analytic
carries a :class:`~omega.ir.Source` so it traces back to its CAR id regardless of what omega does downstream.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from omega.ingest.base import ParseReport
from omega.ir import Atom, Block, CompiledRule, Source

__all__ = ["to_ir", "load_ir"]

_PLATFORMS = {"windows", "linux", "macos"}          # normalised; CAR also uses 'N/A'


def _attack_tags(coverage) -> tuple[str, ...]:
    """CAR ``coverage`` → ATT&CK tags in Sigma's format (``attack.t1543``, ``attack.t1543.003``) so the axis
    aligns across corpora by construction."""
    tags: set[str] = set()
    for entry in coverage or []:
        tech = entry.get("technique")
        if tech:
            tags.add(f"attack.{str(tech).lower()}")
        for sub in entry.get("subtechniques") or []:
            tags.add(f"attack.{str(sub).lower()}")
    return tuple(sorted(tags))


def _logsource(platforms) -> tuple[tuple[str, str], ...]:
    """CAR ``platforms`` → open ``(product, value)`` logsource tags (only recognised platforms)."""
    return tuple(sorted(("product", p.lower()) for p in (platforms or []) if p.lower() in _PLATFORMS))


def _data_model_atoms(refs) -> tuple[Atom, ...]:
    """CAR ``data_model_references`` (``object/action/field``, e.g. ``process/create/exe``) → coarse,
    value-blind field atoms. The field is the last segment — CAR's own vocabulary, not Sigma's."""
    return tuple(Atom(field=r.split("/")[-1], mods=(), values=()) for r in (refs or []) if isinstance(r, str))


def to_ir(analytic: dict, *, path: str | Path | None = None) -> CompiledRule:
    """Map one parsed CAR analytic dict → omega's agnostic IR (the free structured axes; no query parsing)."""
    atoms = _data_model_atoms(analytic.get("data_model_references"))
    blocks = (Block(name="data_model", polarity=1, atoms=atoms),) if atoms else ()
    cid = analytic.get("id")
    return CompiledRule(
        id=cid,
        title=analytic.get("title"),
        logsource=_logsource(analytic.get("platforms")),
        tags=_attack_tags(analytic.get("coverage")),
        blocks=blocks,
        condition="",                                          # CAR has no single boolean condition
        source=Source("car", native_id=cid, path=str(path) if path else None),
    )


def load_ir(root: str | Path, *, pattern: str = "*.yaml") -> tuple[list[CompiledRule], ParseReport]:
    """The CAR adapter's contract entry point: parse every analytic under ``root`` into the agnostic IR plus
    an honest :class:`ParseReport`. Total, deterministic. Analytics whose real logic lives in query-language
    implementations are still ingested at the structured level, and the skipped logic is counted in
    ``deferred['unparsed-implementations']`` — accountable, not hidden."""
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"omega CAR ingest: corpus root not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"omega CAR ingest: corpus root is not a directory: {root}")

    report = ParseReport()
    rules: list[CompiledRule] = []
    for p in sorted(root.rglob(pattern)):
        report.files += 1
        try:
            analytic = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            report.record_error(p, exc)
            continue
        if not isinstance(analytic, dict) or "id" not in analytic:
            report.defer("non-analytic")
            continue
        rules.append(to_ir(analytic, path=p))
        report.rules += 1
        if analytic.get("implementations"):
            report.defer("unparsed-implementations")          # real query logic present, not parsed at atom level
    return rules, report
