"""The Sigma adapter — omega's ingest front-end for Sigma rules, and the ONLY place pySigma is imported.

Stage 0 (this file, now): parse a ruleset directory via pySigma into ``SigmaRule`` objects plus an honest
:class:`ParseReport`. Stage 1 (next, lands here too): map each rule's AST to omega's agnostic IR — after
which no ``SigmaRule`` (and no pySigma import) escapes this adapter, and everything downstream is
ruleset-neutral.

Total, error-isolating, deterministic. Verified on the vendored SigmaHQ corpus: 3,748 files, 3,748 rules,
zero errors.
"""

from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from omega.ingest.base import ParseReport
from omega.ir import Atom, Block, CompiledRule, Source

__all__ = ["ParseReport", "load", "to_ir", "load_ir"]


def _is_correlation(rule: object) -> bool:
    """Correlation rules (multi-rule, windowed) are a different shape than a base detection rule; omega
    analyses base rules first and counts correlations for later. Name-based, to stay robust across the pySigma
    versions that have moved the class between modules."""
    return "Correlation" in type(rule).__name__


def load(root: str | Path, *, pattern: str = "*.yml") -> tuple[list[SigmaRule], ParseReport]:
    """Parse every ``pattern`` file under ``root`` via pySigma. Returns ``(base_rules, report)``.

    Total and error-isolating over corpus *content*: a file pySigma rejects is recorded in the report (path +
    exception kind) and skipped — never crashing, never silently vanishing. Deterministic: files are visited
    in sorted order. Correlation rules are counted but kept out of the returned base-rule stream.

    Raises ``FileNotFoundError`` / ``NotADirectoryError`` if ``root`` is not an existing directory — a wrong
    path is a caller bug, and returning a clean-but-empty report would let it hide behind ``clean``. "Total"
    means robust to a *messy* corpus, not silent about a *missing* one.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"omega ingest: corpus root not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"omega ingest: corpus root is not a directory: {root}")
    report = ParseReport()
    rules: list[SigmaRule] = []
    for p in sorted(root.rglob(pattern)):
        report.files += 1
        try:
            collection = SigmaCollection.from_yaml(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:                            # pySigma raises SigmaError; guard anything else too
            report.record_error(p, exc)
            continue
        for rule in collection.rules:
            if _is_correlation(rule):
                report.defer("correlation")
            else:
                rules.append(rule)
                report.rules += 1
    return rules, report


# ── Stage 1 — map pySigma's AST to omega's agnostic IR (the adapter's second half) ─────────────────

def _modname(mod: type) -> str:
    """Normalise a pySigma modifier CLASS to a stable short name: ``SigmaEndswithModifier`` -> ``endswith``."""
    return mod.__name__.removeprefix("Sigma").removesuffix("Modifier").lower()


def _match_pattern(pattern: str, names: list[str]) -> list[str]:
    """Resolve a condition block-reference to concrete block names: a bare name, a ``prefix_*`` glob, or
    ``them`` (all blocks)."""
    if pattern == "them":
        return list(names)
    if pattern.endswith("*"):
        return [n for n in names if n.startswith(pattern[:-1])]
    return [n for n in names if n == pattern]


def _negated_operand(toks: list[str], i: int, names: list[str]) -> list[str]:
    """The block names the operand starting at ``toks[i]`` (just after a ``not``) refers to. Handles the
    standard Sigma forms: a bare ``<name>``, ``all|any|<N> of <pattern>``, and a parenthesised ``( a or b )``."""
    if i >= len(toks):
        return []
    t = toks[i]
    if (t.lower() in ("all", "any") or t.isdigit()) and i + 2 < len(toks) and toks[i + 1].lower() == "of":
        return _match_pattern(toks[i + 2], names)
    if t == "(":
        depth, j, found = 1, i + 1, []
        while j < len(toks) and depth:
            if toks[j] == "(":
                depth += 1
            elif toks[j] == ")":
                depth -= 1
            elif toks[j].lower() not in ("and", "or", "not"):
                found += _match_pattern(toks[j], names)
            j += 1
        return found
    return _match_pattern(t, names)


def _block_polarities(condition: str, names: list[str]) -> dict[str, int]:
    """Read each block's polarity from the condition: ``-1`` if it is referenced under a ``not`` (a filter),
    else ``+1`` (a selection). Covers the standard Sigma grammar (``selection and not 1 of filter_*``,
    ``all of selection_*``, ``not (a or b)``); it does not model full boolean precedence, so an unusual
    condition may mis-sign a block — the raw condition is kept on the IR so this can be hardened later."""
    pol = {n: 1 for n in names}
    toks = condition.replace("(", " ( ").replace(")", " ) ").split()
    for i, t in enumerate(toks):
        if t.lower() == "not":
            for b in _negated_operand(toks, i + 1, names):
                pol[b] = -1
    return pol


def _atoms(detection) -> list[Atom]:
    """Flatten a (possibly nested) ``SigmaDetection`` into its atoms. A block written as a *list of maps* is a
    nested ``SigmaDetection`` per map, so ``detection_items`` can hold sub-detections as well as field tests.
    omega reads the block's atom SET, so nesting is flattened — the intra-block and/or grouping is not
    preserved (a later refinement if a use needs it)."""
    out: list[Atom] = []
    for item in detection.detection_items:
        if hasattr(item, "detection_items"):                    # a nested SigmaDetection -> recurse
            out.extend(_atoms(item))
        else:                                                   # a SigmaDetectionItem (field/value test)
            out.append(Atom(
                field=item.field,
                mods=tuple(_modname(m) for m in (item.modifiers or [])),
                values=tuple(str(v) for v in (item.value or [])),
            ))
    return out


def to_ir(rule: SigmaRule) -> CompiledRule:
    """Lower a parsed pySigma rule to omega's agnostic :class:`~omega.ir.CompiledRule`. Total by construction
    — it *reads* fields, it does not evaluate — so every base rule maps. After this, no ``SigmaRule`` escapes.
    (Multi-condition rules use the first condition for polarity; rare, and the raw string is retained.)"""
    det = rule.detection
    condition = det.condition[0] if det.condition else ""
    polarity = _block_polarities(condition, list(det.detections))
    blocks = tuple(
        Block(name=name, polarity=polarity.get(name, 1), atoms=tuple(_atoms(detection)))
        for name, detection in det.detections.items()
    )
    ls = rule.logsource
    logsource = tuple(sorted(                                   # open (dimension, value) pairs, only-present
        (dim, val) for dim, val in (("category", ls.category), ("product", ls.product), ("service", ls.service))
        if val is not None
    ))
    native_id = str(rule.id) if rule.id else None
    return CompiledRule(
        id=native_id,
        title=rule.title,
        logsource=logsource,
        tags=tuple(str(t) for t in (rule.tags or [])),
        blocks=blocks,
        condition=condition,
        source=Source("sigma", native_id=native_id),           # path threading deferred; native id is the key
    )


def load_ir(root: str | Path, *, pattern: str = "*.yml") -> tuple[list[CompiledRule], ParseReport]:
    """The full Sigma adapter: :func:`load` then :func:`to_ir` on every base rule. Returns the agnostic IR
    plus the parse report — this is the ``(list[CompiledRule], ParseReport)`` contract every adapter meets."""
    rules, report = load(root, pattern=pattern)
    return [to_ir(r) for r in rules], report
