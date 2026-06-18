"""Minimal Sigma-subset evaluator — run a community Sigma rule against a flat event, honestly.

A faithful subset, not a full Sigma engine: it evaluates the common shape — a ``selection`` block
(AND across keys) with ``field|modifier`` matches (``contains``/``startswith``/``endswith``/``all``,
case-insensitive Windows string semantics), optionally suppressed by ``filter*`` blocks under a
``selection and not 1 of filter*`` condition. Rules whose condition or value-shapes fall outside this
subset are NOT evaluable (the caller reports them as NONE — abstain — never as a silent no-vote).

This is the corroboration substrate: :mod:`detection.sigma_panel` dedups rules into equivalence
classes and runs one representative per class through :func:`rule_fires`.
"""

from __future__ import annotations

import string

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _ascii_lower(s: str) -> str:
    """ASCII-only lowercase (A–Z → a–z), every other code point left unchanged — the pinned case-fold of the
    IR semantics profile (``design/detection_ir_semantics.md``). Identical across Python / Rust
    (``make_ascii_lowercase``) / a byte-wise SPARQL fold, so emitters agree by targeting the spec rather than
    their language's Unicode ``.lower()``. On ASCII input (Windows paths, DLLs) it equals ``str.lower()`` — so
    this is non-regressive on real Sigma rules; it diverges from full-Unicode folding only on non-ASCII case
    pairs, where it removes a silent cross-emitter disagreement."""
    return s.translate(_ASCII_LOWER)


def field_matches(event_val, spec, mods: set[str]) -> bool:
    """One ``field|mods: spec`` clause. A list ``spec`` is OR unless ``|all`` makes it AND.
    Case-insensitive per the IR semantics profile — **ASCII-only** case-fold (``design/detection_ir_semantics.md``),
    not full-Unicode, so the Python/SPARQL/Rust emitters share one definition."""
    ev = _ascii_lower(str(event_val))
    patterns = spec if isinstance(spec, list) else [spec]

    def one(p) -> bool:
        p = _ascii_lower(str(p))
        if "endswith" in mods:
            return ev.endswith(p)
        if "startswith" in mods:
            return ev.startswith(p)
        if "contains" in mods:
            return p in ev
        return ev == p

    return all(one(p) for p in patterns) if "all" in mods else any(one(p) for p in patterns)


def block_matches(block: dict, event: dict) -> bool:
    """A selection/filter block is an AND across its keys."""
    for key, spec in block.items():
        field, *mods = key.split("|")
        if not field_matches(event.get(field, ""), spec, set(mods)):
            return False
    return True


def is_evaluable(rule: dict) -> bool:
    """True iff this evaluator can faithfully run the rule: a ``selection`` (optionally
    ``and not ... filter``) condition over a flat field-map selection (no nested blocks)."""
    det = rule.get("detection")
    if not isinstance(det, dict):
        return False
    cond = str(det.get("condition", "")).strip()
    ok_cond = cond == "selection" or (cond.startswith("selection and not") and "filter" in cond)
    sel = det.get("selection")
    if not ok_cond or not isinstance(sel, dict):
        return False
    return all(not isinstance(v, dict) for v in sel.values())   # flat field-maps only


def evaluate_rule(rule: dict, event: dict) -> dict:
    """Full result: did ``selection`` match, which ``filter*`` blocks suppressed it, does it fire."""
    det = rule["detection"]
    selection = block_matches(det["selection"], event)
    filters = {k: block_matches(v, event) for k, v in det.items()
               if k.startswith("filter") and isinstance(v, dict)}
    suppressed_by = [k for k, hit in filters.items() if hit]
    return {"selection": selection, "suppressed_by": suppressed_by,
            "fires": selection and not suppressed_by}          # `selection and not 1 of filter*`


def rule_fires(rule: dict, event: dict) -> bool:
    """Does this Sigma rule fire on ``event`` (selection matched, no filter suppressed it)?"""
    return evaluate_rule(rule, event)["fires"]
