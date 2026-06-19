"""The complete detection IR — a typed, content-addressed representation of a *whole* rule, the thing a fast
emitter (Rust / a vectorized engine / Substrait) targets.

The motif ``MotifGraph`` represents only the simple ``selection [and not 1 of filter*]`` case; the general
detection logic we built (boolean conditions over named blocks, keyword blocks, the full modifier set) lived in
Python code (``sigma_eval``/``condition``), not in any IR. This module folds all of it into one typed IR:

    CompiledRule = rule_id + blocks (parsed molecules) + condition (the boolean/quantifier AST)
    Block        = "and" (a field-map) | "or" (list-of-maps) | "keyword" (whole-event substring)
    Clause       = field + the FULL modifier set + values

``eval_ir`` is the canonical interpreter. It is **proven faithful** to the existing raw evaluator
(:func:`attest_ir_faithful`): both bottom out in :func:`detection.sigma_eval.field_matches` and share the one
condition walker (:func:`detection.condition.eval_ast`), so the typed IR computes identically — that proof is
what licenses emitting from the IR instead of the raw rule dict.

Step 1 of the IR fold: this complete IR + interpreter + faithfulness proof. Next: migrate the emitters (Python
``eval_python``, SPARQL) onto it and retire the partial ``MotifGraph``, so there is ONE IR with N attested emitters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from provenance import evidence_digest

from detection.condition import _keyword_hit, eval_ast, parse_condition
from detection.sigma_eval import field_matches, is_evaluable


@dataclass(frozen=True)
class Clause:
    """One ``field|mods: values`` clause, carrying the FULL Sigma modifier set (op + re/cidr/gt-lt/windash/all/…)."""

    field: str
    mods: tuple[str, ...]
    values: tuple

    def matches(self, event: dict) -> bool:
        return field_matches(event.get(self.field, ""), list(self.values), set(self.mods))

    def as_tuple(self) -> tuple:
        return (self.field, tuple(self.mods), tuple(self.values))


@dataclass(frozen=True)
class Block:
    """A named detection block: a field-map (``and``), a list-of-maps (``or``), or a keyword list."""

    name: str
    kind: str                          # "and" | "or" | "keyword"
    maps: tuple = ()                   # for and/or: tuple of maps, each a tuple[Clause] (AND of clauses)
    keywords: tuple = ()               # for keyword: tuple[str]

    def matches(self, event: dict) -> bool:
        if self.kind == "keyword":
            return any(_keyword_hit(str(k), event) for k in self.keywords)
        return any(all(c.matches(event) for c in m) for m in self.maps)   # OR of maps, AND within a map

    def as_tuple(self) -> tuple:
        return (self.name, self.kind, tuple(tuple(c.as_tuple() for c in m) for m in self.maps),
                tuple(self.keywords))


@dataclass(frozen=True)
class CompiledRule:
    """A whole rule as a typed IR: named blocks + the condition AST. Content-addressed by its structure."""

    rule_id: str
    blocks: tuple
    condition: tuple

    def block_map(self) -> dict:
        return {b.name: b for b in self.blocks}

    @property
    def cid(self) -> str:
        body = {"rule_id": self.rule_id, "blocks": [b.as_tuple() for b in self.blocks],
                "condition": self.condition}
        return evidence_digest(json.dumps(body, sort_keys=True, separators=(",", ":"), default=list))

    def to_dict(self) -> dict:
        """The wire form a non-Python emitter (the Rust crate) consumes: named blocks with parsed clauses +
        the condition AST (tuples serialize to JSON arrays)."""
        return {
            "rule_id": self.rule_id,
            "blocks": [{"name": b.name, "kind": b.kind,
                        "maps": [[{"field": c.field, "mods": list(c.mods), "values": list(c.values)} for c in m]
                                 for m in b.maps],
                        "keywords": list(b.keywords)} for b in self.blocks],
            "condition": self.condition,
        }


def _parse_clause(key: str, spec) -> Clause:
    field, *mods = key.split("|")
    values = tuple(str(v) for v in (spec if isinstance(spec, list) else [spec]))
    return Clause(field, tuple(sorted(mods)), values)


def _parse_block(name: str, b) -> Block:
    if isinstance(b, dict):
        return Block(name, "and", (tuple(_parse_clause(k, v) for k, v in b.items()),))
    if isinstance(b, list) and b and all(isinstance(m, dict) for m in b):
        return Block(name, "or", tuple(tuple(_parse_clause(k, v) for k, v in m.items()) for m in b))
    if isinstance(b, list):
        return Block(name, "keyword", keywords=tuple(str(x) for x in b))
    return Block(name, "keyword", keywords=(str(b),))


def compile_rule(rule: dict) -> CompiledRule:
    """Compile an evaluable Sigma rule into the complete typed IR (raises if outside the evaluable subset)."""
    if not is_evaluable(rule):
        raise ValueError(f"rule {rule.get('id', '?')} is outside the evaluable subset")
    det = rule["detection"]
    blocks = tuple(_parse_block(name, b) for name, b in det.items() if name != "condition")
    return CompiledRule(rule.get("id", "?"), blocks, parse_condition(str(det["condition"])))


def eval_ir(ir: CompiledRule, event: dict) -> bool:
    """The canonical IR interpreter: evaluate the condition AST over the parsed blocks. Shares the AST walker
    with the raw evaluator and bottoms out in ``field_matches`` — so it computes identically (see
    :func:`attest_ir_faithful`)."""
    bm = ir.block_map()
    return eval_ast(ir.condition, list(bm), lambda name: name in bm and bm[name].matches(event))


def attest_ir_faithful(rules: list[dict], events: list[dict]) -> dict:
    """The fold's correctness proof: for every (evaluable rule, event), the IR interpreter agrees with the raw
    evaluator — ``eval_ir(compile_rule(rule), e) == evaluate_rule(rule, e)['fires']``. ``faithful`` iff no
    disagreement; any disagreement localizes (rule, event) where the typed IR diverges from the raw path."""
    from detection.sigma_eval import evaluate_rule

    dis = []
    for rule in rules:
        ir = compile_rule(rule)
        for e in events:
            if eval_ir(ir, e) != evaluate_rule(rule, e)["fires"]:
                dis.append({"rule": rule.get("id", "?"), "event": evidence_digest(
                    json.dumps(e, sort_keys=True, separators=(",", ":"), default=str))})
    return {"checked": len(rules) * len(events), "n_rules": len(rules),
            "disagreements": dis, "faithful": not dis}
