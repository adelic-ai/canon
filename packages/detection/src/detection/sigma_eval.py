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

import re
import string
from functools import lru_cache

from detection.condition import condition_parses, eval_condition, match_block

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _ascii_lower(s: str) -> str:
    """ASCII-only lowercase (A–Z → a–z), every other code point left unchanged — the pinned case-fold of the
    IR semantics profile (``design/detection_ir_semantics.md``). Identical across Python / Rust
    (``make_ascii_lowercase``) / a byte-wise SPARQL fold, so emitters agree by targeting the spec rather than
    their language's Unicode ``.lower()``. On ASCII input (Windows paths, DLLs) it equals ``str.lower()`` — so
    this is non-regressive on real Sigma rules; it diverges from full-Unicode folding only on non-ASCII case
    pairs, where it removes a silent cross-emitter disagreement."""
    return s.translate(_ASCII_LOWER)


def has_wildcard(p: str) -> bool:
    """True iff ``p`` contains an *unescaped* Sigma wildcard (``*`` or ``?``)."""
    i = 0
    while i < len(p):
        if p[i] == "\\" and i + 1 < len(p):
            i += 2
            continue
        if p[i] in "*?":
            return True
        i += 1
    return False


def needs_regex(p: str) -> bool:
    """True iff a plain string op (``CONTAINS``/``STRENDS``/``=``) would MISREPRESENT ``p`` — i.e. it has an
    unescaped wildcard, OR an escape sequence (``\\*`` ``\\?`` ``\\\\``) whose *literal* differs from the raw
    text. Only wildcard-free, escape-free patterns may take an emitter's fast string-op path; everything else
    must compile :func:`glob_regex_body`. (A lone ``\\`` before a normal char is a literal backslash and is
    fine on the fast path — Windows paths like ``\\lsass.exe`` stay fast.)"""
    i = 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            if p[i + 1] in "*?\\":
                return True          # an escape whose literal differs from the raw text
            i += 2                   # lone backslash before a normal char — literal, fast path ok
            continue
        if c in "*?":
            return True
        i += 1
    return False


def _glob_body(p: str) -> str:
    """Translate a (case-folded) Sigma glob value to a regex body, the Sigma string-escape convention:
    ``*`` → ``.*`` (any run), ``?`` → ``.`` (one char), ``\\*`` / ``\\?`` / ``\\\\`` → the literal char,
    a lone ``\\`` → a literal backslash, everything else regex-escaped. The naive ``replace('*', '.*')`` is
    wrong because Sigma values are full of regex metacharacters (``.`` in ``comsvcs.dll``, ``+`` in
    ``lsass.exe+``, ``\\`` in paths) — every literal run is ``re.escape``\\d here."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p) and p[i + 1] in "*?\\":
            out.append(re.escape(p[i + 1]))
            i += 2
        elif c == "*":
            out.append(".*")
            i += 1
        elif c == "?":
            out.append(".")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


@lru_cache(maxsize=8192)
def glob_regex_body(pattern_lower: str, op: str) -> str:
    """The shared regex body (no anchors, no flags) for a case-folded pattern under a modifier — the SINGLE
    definition the Python and (future) SPARQL/Rust emitters compile, so they glob identically by
    construction. Modifiers are sugar over the glob: ``contains`` x ≡ ``*x*``, ``startswith`` x ≡ ``x*``,
    ``endswith`` x ≡ ``*x``, plain x ≡ ``x`` (a full match). Anchoring + DOTALL are each emitter's job."""
    body = _glob_body(pattern_lower)
    if op == "contains":
        return f".*{body}.*"
    if op == "startswith":
        return f"{body}.*"
    if op == "endswith":
        return f".*{body}"
    return body


@lru_cache(maxsize=8192)
def _compiled(pattern_lower: str, op: str):
    return re.compile(glob_regex_body(pattern_lower, op), re.DOTALL)


def _op(mods: set[str]) -> str:
    for m in ("endswith", "startswith", "contains"):
        if m in mods:
            return m
    return "eq"


@lru_cache(maxsize=4096)
def _re_compiled(pattern: str, ignorecase: bool):
    return re.compile(pattern, re.IGNORECASE if ignorecase else 0)


def _re_search(pattern: str, ignorecase: bool, text: str) -> bool:
    """``|re`` — regex search (case-sensitive by default per Sigma; ``|i`` adds IGNORECASE). NOT ascii-folded;
    the regex author controls case."""
    try:
        return _re_compiled(pattern, ignorecase).search(text) is not None
    except re.error:
        return False


def _cidr_match(ip_str: str, cidr: str) -> bool:
    """``|cidr`` — is the event IP inside the rule's subnet."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip_str.strip()) in ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return False


def _num_cmp(val, pat, op: str) -> bool:
    """``|gt|gte|lt|lte`` — numeric comparison (non-numeric operands → no match)."""
    try:
        x, y = float(val), float(pat)
    except (TypeError, ValueError):
        return False
    return {"gt": x > y, "gte": x >= y, "lt": x < y, "lte": x <= y}[op]


@lru_cache(maxsize=8192)
def _compiled_windash(pattern_lower: str, op: str):
    """``|windash`` — like the glob compile, but each ``-`` in the pattern matches any CLI dash variant
    (``- / – — ―``), the trick attackers use to evade flag-string detection."""
    out, i = [], 0
    while i < len(pattern_lower):
        c = pattern_lower[i]
        if c == "\\" and i + 1 < len(pattern_lower) and pattern_lower[i + 1] in "*?\\":
            out.append(re.escape(pattern_lower[i + 1])); i += 2
        elif c == "*":
            out.append(".*"); i += 1
        elif c == "?":
            out.append("."); i += 1
        elif c == "-":
            out.append("[-/–—―]"); i += 1
        else:
            out.append(re.escape(c)); i += 1
    body = "".join(out)
    body = {"contains": f".*{body}.*", "startswith": f"{body}.*", "endswith": f".*{body}"}.get(op, body)
    return re.compile(body, re.DOTALL)


def field_matches(event_val, spec, mods: set[str]) -> bool:
    """One ``field|mods: spec`` clause. A list ``spec`` is OR unless ``|all`` makes it AND.

    Default match (per ``design/detection_ir_semantics.md``): **ASCII-only** case-fold + **Sigma glob**
    (``*``/``?`` → anchored DOTALL regex via :func:`glob_regex_body`). Value-transform / alternate-match
    modifiers handled here: ``re`` (regex), ``cidr`` (subnet), ``gt|gte|lt|lte`` (numeric), ``windash``
    (CLI-dash variants). Modifiers not handled abstain upstream (``evaluability`` → ``unsupported-modifier``)
    rather than mis-fire."""
    patterns = spec if isinstance(spec, list) else [spec]
    combine = all if "all" in mods else any

    if "re" in mods:                                    # regex — not ascii-folded; |i = case-insensitive
        text = str(event_val)
        return combine(_re_search(str(p), "i" in mods, text) for p in patterns)
    if "cidr" in mods:
        return combine(_cidr_match(str(event_val), str(p)) for p in patterns)
    num_op = next((m for m in ("gte", "lte", "gt", "lt") if m in mods), None)
    if num_op:
        return combine(_num_cmp(event_val, p, num_op) for p in patterns)

    ev = _ascii_lower(str(event_val))
    op = _op(mods)
    if "windash" in mods:
        return combine(_compiled_windash(_ascii_lower(str(p)), op).fullmatch(ev) is not None for p in patterns)
    return combine(_compiled(_ascii_lower(str(p)), op).fullmatch(ev) is not None for p in patterns)


def block_matches(block: dict, event: dict) -> bool:
    """A selection/filter block is an AND across its keys."""
    for key, spec in block.items():
        field, *mods = key.split("|")
        if not field_matches(event.get(field, ""), spec, set(mods)):
            return False
    return True


_SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "eq",   # glob + default
                   "re", "i", "cidr", "gt", "gte", "lt", "lte", "windash"}   # value-transform / alt-match mods


def _map_reason(m: dict) -> str | None:
    """``None`` if a field-map block is faithfully evaluable, else why not. Guards against silently
    mis-evaluating a clause: a nested value, or a modifier (``|re``/``|base64``/``|cidr``/``|gt``…) that
    ``field_matches`` would wrongly treat as a literal — those must abstain, not fire incorrectly."""
    for k, v in m.items():
        if isinstance(v, dict):
            return "nested-selection"
        if set(str(k).split("|")[1:]) - _SUPPORTED_MODS:
            return "unsupported-modifier"
    return None


def evaluability(rule: dict) -> tuple[bool, str]:
    """Whether the evaluator can faithfully run the rule, **and why not** — the reason drives the Sigma
    audit's roadmap (which construct blocks the most rules). Reasons, in classification order:

    * ``correlation`` — a Sigma correlation rule (multi-rule, windowed): a stateful fold, not a per-event
      match (compiles to the subgraph/temporal primitives, handled separately);
    * ``aggregation`` — a ``| count()/sum()/near`` condition: a stateful group-fold (compiles to the fanout
      primitive, handled separately);
    * ``no-detection`` / ``no-condition`` / ``no-blocks`` — missing the structures we evaluate;
    * ``nested-selection`` — a block's values are nested maps (not flat field-maps);
    * ``unsupported-block`` — a block that is a keyword list / scalar (whole-event substring search), not yet
      compiled;
    * ``condition-unsupported`` — a boolean condition outside the supported grammar (see
      :mod:`detection.condition`);
    * ``ok`` — compiles to firing code (general boolean condition over flat-field-map named blocks).
    """
    if rule.get("correlation") is not None or rule.get("type") == "correlation":
        return False, "correlation"
    det = rule.get("detection")
    if not isinstance(det, dict):
        return False, "no-detection"
    cond = str(det.get("condition", "")).strip()
    if not cond:
        return False, "no-condition"
    if "|" in cond and any(a in cond.lower() for a in ("count(", "sum(", "avg(", "min(", "max(", " near ")):
        return False, "aggregation"
    blocks = {k: v for k, v in det.items() if k != "condition"}
    if not blocks:
        return False, "no-blocks"
    for b in blocks.values():                                   # blocks: flat field-map, list-of-maps, or keyword(s)
        if isinstance(b, dict):
            r = _map_reason(b)
            if r:
                return False, r
        elif isinstance(b, list):
            if b and all(isinstance(m, dict) for m in b):
                for m in b:
                    r = _map_reason(m)
                    if r:
                        return False, r
            elif not all(isinstance(m, (str, int, float, bool)) for m in b):
                return False, "unsupported-block"               # mixed/odd list (not maps, not keywords)
            # else: a keyword list of scalars → ok
        elif not isinstance(b, (str, int, float, bool)):        # a scalar keyword is ok; None/other is not
            return False, "unsupported-block"
    if not condition_parses(cond):
        return False, "condition-unsupported"
    return True, "ok"


def is_evaluable(rule: dict) -> bool:
    """True iff the motif matcher can faithfully run the rule — a ``selection`` (optionally ``and not 1 of
    filter*``) condition over a flat field-map selection. See :func:`evaluability` for the reason."""
    return evaluability(rule)[0]


def evaluate_rule(rule: dict, event: dict) -> dict:
    """Full result for a rule on an event. ``fires`` is the **general** boolean condition over the rule's
    named blocks (:func:`detection.condition.eval_condition`). The ``selection``/``suppressed_by`` fields are
    kept for cause analysis (fidelity uses ``suppressed_by`` to tell an allowlist suppression from a selection
    gap): whether a ``selection`` block matched, and which ``filter*`` blocks matched on this event."""
    det = rule["detection"]
    fires = eval_condition(det, event)
    suppressed_by = [k for k, v in det.items() if k.startswith("filter") and match_block(v, event)]
    sel = det.get("selection")
    selection = match_block(sel, event) if sel is not None else None
    return {"selection": selection, "suppressed_by": suppressed_by, "fires": fires}


def rule_fires(rule: dict, event: dict) -> bool:
    """Does this Sigma rule fire on ``event`` (selection matched, no filter suppressed it)?"""
    return evaluate_rule(rule, event)["fires"]
