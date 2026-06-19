"""Sigma condition parser + evaluator — general boolean conditions over arbitrarily-named blocks.

The consumption audit measured that the #1 blocker to compiling Sigma to firing code is NOT
aggregation/correlation but rules that name their detection blocks something other than ``selection`` and
combine them with arbitrary boolean conditions (``all of selection_*``, ``selection_a and selection_b``,
``1 of them``, ``(a or b) and not filter``). This compiles that grammar to real Python firing code (the
reference runtime), the highest-leverage coverage widening.

Grammar (recursive descent); aggregation (``| count()...``) is excluded — a separate, stateful concern
handled upstream:

    or    := and ('or' and)*
    and   := unary ('and' unary)*
    unary := 'not' unary | atom
    atom  := '(' or ')' | quantifier | IDENT
    quantifier := (NUMBER | 'all' | '1') 'of' (GLOB | 'them')

The AST is plain tuples: ``('and'|'or', [nodes])`` · ``('not', node)`` · ``('ref', name)`` ·
``('quant', n|None, pattern)`` (``n=None`` means *all*).
"""

from __future__ import annotations

import fnmatch
import re

_TOK = re.compile(r"[()]|[A-Za-z0-9_.*?\-]+")
_STOP = {")", "and", "or", "of", "them"}


def _tokenize(cond: str) -> list[str]:
    return _TOK.findall(cond)


class _Parser:
    def __init__(self, toks: list[str]):
        self.toks = toks
        self.i = 0

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self):
        t = self._peek()
        self.i += 1
        return t

    def parse(self):
        node = self._or()
        if self.i != len(self.toks):
            raise ValueError(f"trailing tokens: {self.toks[self.i:]}")
        return node

    def _or(self):
        nodes = [self._and()]
        while self._peek() == "or":
            self._next()
            nodes.append(self._and())
        return ("or", nodes) if len(nodes) > 1 else nodes[0]

    def _and(self):
        nodes = [self._unary()]
        while self._peek() == "and":
            self._next()
            nodes.append(self._unary())
        return ("and", nodes) if len(nodes) > 1 else nodes[0]

    def _unary(self):
        if self._peek() == "not":
            self._next()
            return ("not", self._unary())
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t == "(":
            self._next()
            node = self._or()
            if self._next() != ")":
                raise ValueError("expected ')'")
            return node
        if t == "all" or (t is not None and t.isdigit()):
            return self._quantifier()
        if t is None or t in _STOP:
            raise ValueError(f"unexpected token {t!r}")
        return ("ref", self._next())

    def _quantifier(self):
        q = self._next()                                # 'all' | a number
        if self._next() != "of":
            raise ValueError("expected 'of'")
        pat = self._next()
        if pat is None or pat in (_STOP - {"them"}) or pat == "(":
            raise ValueError("expected a pattern after 'of'")
        return ("quant", None if q == "all" else int(q), pat)


def parse_condition(cond: str):
    """Parse a Sigma condition into the tuple-AST. Raises ``ValueError`` on anything outside the grammar."""
    return _Parser(_tokenize(cond)).parse()


def condition_parses(cond: str) -> bool:
    """True iff the condition is within the supported boolean/quantifier grammar (no aggregation ``|``)."""
    if "|" in cond:
        return False
    try:
        parse_condition(cond)
        return True
    except (ValueError, KeyError):
        return False


def _keyword_hit(kw: str, event: dict) -> bool:
    """A Sigma **keyword** matches if it appears (case-insensitive contains-glob) in ANY field value of the
    event — the whole-event substring search Sigma keyword lists do over the raw log."""
    from detection.sigma_eval import field_matches
    return any(field_matches(v, kw, {"contains"}) for v in event.values())


def match_block(block, event: dict) -> bool:
    """Match one detection block against an event:

    * ``dict`` — AND across its field clauses (a field-map);
    * ``list`` of dicts — OR across those maps (Sigma's list-of-maps);
    * ``list`` of strings / a scalar — a **keyword** block: OR of whole-event substring searches.

    Field semantics come from :func:`detection.sigma_eval.field_matches` (imported lazily — import cycle)."""
    from detection.sigma_eval import block_matches
    if isinstance(block, dict):
        return block_matches(block, event)
    if isinstance(block, list):
        if block and all(isinstance(m, dict) for m in block):
            return any(block_matches(m, event) for m in block)         # list of field-maps (OR)
        return any(_keyword_hit(str(kw), event) for kw in block)       # keyword list (OR)
    if isinstance(block, (str, int, float, bool)):
        return _keyword_hit(str(block), event)                         # single keyword
    return False


def eval_ast(node: tuple, names: list, block_eval) -> bool:
    """Evaluate a parsed condition AST. ``names`` = the available block names (for quantifier globs);
    ``block_eval(name) -> bool`` resolves a single named block. **Shared** by the raw evaluator
    (:func:`eval_condition`, over raw dict blocks) and the IR interpreter (``rule_ir.eval_ir``, over parsed
    molecule blocks) — so the boolean/quantifier semantics have ONE definition, not two that can drift."""
    kind = node[0]
    if kind == "and":
        return all(eval_ast(n, names, block_eval) for n in node[1])
    if kind == "or":
        return any(eval_ast(n, names, block_eval) for n in node[1])
    if kind == "not":
        return not eval_ast(node[1], names, block_eval)
    if kind == "ref":
        return block_eval(node[1])
    if kind == "quant":
        n, pat = node[1], node[2]
        sel = names if pat == "them" else fnmatch.filter(names, pat)
        matched = sum(1 for nm in sel if block_eval(nm))
        return (len(sel) > 0 and matched == len(sel)) if n is None else matched >= n
    raise ValueError(f"bad node {node!r}")


def eval_condition(detection: dict, event: dict) -> bool:
    """Evaluate a detection's ``condition`` (general boolean over its named blocks) against an event."""
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    return eval_ast(parse_condition(str(detection.get("condition", ""))), list(blocks),
                    lambda name: name in blocks and match_block(blocks[name], event))


def rule_fires_general(rule: dict, event: dict) -> bool:
    """Does ``rule`` fire on ``event`` under the general condition grammar."""
    return eval_condition(rule.get("detection", {}), event)
