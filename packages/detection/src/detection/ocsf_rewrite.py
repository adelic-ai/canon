"""Sigma→OCSF rule rewrite — the rules-side of the OFF-able normalization waist (step 3).

Step 2 normalized *events* onto OCSF attribute paths. This is the matching move on *rules*:
rewrite a compiled rule's field references from its native source vocabulary (Sysmon
``TargetImage``/``CommandLine``/…) onto the same OCSF paths, so a rule and an OCSF-normalized
event speak one vocabulary and the round fires a coherent pair. Once rewritten, the *same*
rule fires against an OCSF event from **any** source whose adapter targets those paths — the
cross-source rule reuse that normalizing buys.

It is a **pass over the IR**, not a new engine: walk blocks → maps → clauses, replace each
``Clause.field`` with its OCSF path (looked up through the same graded field map the event
adapter uses), and leave the structure, modifiers, values, and condition AST untouched. The
firing engine (``eval_ir`` / ``motif-rs``) is unchanged — it just keys on OCSF field strings
now. (This is the IR-as-spine framing made concrete: a normalization is a pass.)

Graded and lossy, never assumed faithful — the same discipline as the event side:

- Each rewritten field carries its SKOS grade; :attr:`RewrittenRule.grade` is the worst grade
  across the rule's mapped fields (a rule is only as faithful as its weakest field).
- A field with **no OCSF home** (Sysmon ``CallTrace`` — the call stack has no OCSF attribute)
  is the honest failure case. The clause is dropped and **loudly reported** in
  :attr:`RewrittenRule.dropped`, and :attr:`RewrittenRule.faithful` goes ``False``. Dropping a
  clause from an AND makes the rule *more permissive* (it can no longer test the field it
  lost) → it will **over-match** against OCSF events. That over-match is the real consequence
  of the loss, surfaced — not hidden, and exactly what the step-4 faithfulness gate enumerates
  (native catches comsvcs via CallTrace; the OCSF-rewritten rule can't, so it fires wider).
"""

from __future__ import annotations

from dataclasses import dataclass

from detection.ocsf_adapter import EXACT, SourceAdapter
from detection.rule_ir import Block, Clause, CompiledRule, compile_rule, eval_ir
from detection.vocab import OCSF

# grade ordering for "worst grade wins" — a rule is only as faithful as its weakest field.
_GRADE_RANK = {"exact": 0, "close": 1, "broad": 2, "narrow": 2}


@dataclass(frozen=True)
class RewrittenRule:
    """A rule rewritten onto OCSF field paths, plus the honest record of the rewrite.

    ``rule`` is the rewritten IR (OCSF field names; clauses whose field had no OCSF home are
    dropped). ``mapped`` is ``(native_field, ocsf_path, grade)`` per rewritten field;
    ``dropped`` is the native fields with no OCSF home (the loss)."""

    rule: CompiledRule
    mapped: tuple[tuple[str, str, str], ...]
    dropped: tuple[str, ...]

    @property
    def faithful(self) -> bool:
        """True iff no field was lost (every clause field had an OCSF home). A faithful rewrite
        of an all-``exact`` rule fires identically on OCSF events; any drop means it over-matches."""
        return not self.dropped

    @property
    def grade(self) -> str:
        """The rule's overall grade — worst across its mapped fields, or ``"unfaithful"`` if any
        field was dropped (a dropped load-bearing field is worse than any graded edge)."""
        if self.dropped:
            return "unfaithful"
        if not self.mapped:
            return EXACT
        return max((g for _, _, g in self.mapped), key=lambda g: _GRADE_RANK.get(g, 2))


def _rewrite_clauses(clauses: tuple, adapter: SourceAdapter,
                     mapped: dict[str, tuple[str, str, str]], dropped: list[str]) -> tuple:
    """Rewrite one AND-map of clauses: remap each clause's field to its OCSF path, dropping
    (and recording) any clause whose field has no OCSF home. Modifiers and values are carried
    verbatim — only the field name changes."""
    out = []
    for c in clauses:
        m = adapter.ocsf_for(c.field)
        if m is None:
            if c.field not in dropped:
                dropped.append(c.field)
            continue
        mapped[c.field] = (c.field, m.ocsf_path, m.grade)
        out.append(Clause(m.ocsf_path, c.mods, c.values))
    return tuple(out)


def rewrite_rule_to_ocsf(ir: CompiledRule, adapter: SourceAdapter) -> RewrittenRule:
    """Rewrite a compiled rule's field references onto OCSF attribute paths via ``adapter``.

    Keyword blocks (full-text Sigma keywords, no field) are left untouched — they search free
    text, not a field, so there is no field to remap (a separate concern; flagged by not being
    counted as mapped). The condition AST and block structure are preserved exactly."""
    mapped: dict[str, tuple[str, str, str]] = {}
    dropped: list[str] = []
    new_blocks = []
    for b in ir.blocks:
        if b.kind == "keyword":
            new_blocks.append(b)
            continue
        new_maps = tuple(_rewrite_clauses(m, adapter, mapped, dropped) for m in b.maps)
        new_blocks.append(Block(b.name, b.kind, new_maps, b.keywords))
    rewritten = CompiledRule(ir.rule_id, tuple(new_blocks), ir.condition)
    return RewrittenRule(
        rule=rewritten,
        mapped=tuple(mapped.values()),
        dropped=tuple(dropped),
    )


def ocsf_vocab(adapter: SourceAdapter):
    """The vocabulary OCSF-rewritten rules speak — the adapter's target vocab, so a round can
    assert the rewritten rules cohere with OCSF-normalized events before firing."""
    v = adapter.vocabulary()
    assert v.name == OCSF, f"adapter target is {v.name}, not ocsf"
    return v


def attest_ocsf_agreement(rule_dicts: list[dict], events: list[dict], adapter: SourceAdapter) -> dict:
    """Native-as-oracle faithfulness gate for OCSF normalization (step 4) — the acceptance test
    for the whole slice, mirroring :func:`~detection.rule_ir.attest_ir_faithful` and
    :func:`~detection.rust_emitter.attest_rust_agreement`.

    Fire every rule on every event **both ways**: NATIVE (rule + event in the source
    vocabulary) vs OCSF (rule rewritten via ``adapter`` + event normalized via ``adapter``).
    Native is ground truth. The discipline that makes OCSF safe to turn on:

    - A **faithful, all-exact** rewrite *must* agree on every event — an exact field-rename plus
      an identity event copy compute the same match. A divergence there is **unexplained** and
      **fails the gate** (a real faithfulness bug, localized to the (rule, event)).
    - A **lossy** rewrite (a dropped no-OCSF-home field, or a non-``exact`` mapped field whose
      event-side value was transformed — e.g. the eslogger argv join) *may* diverge, and the
      divergence is **explained** by that tracked field — the cause is recorded, never silent.

    ``attested`` iff there are **zero unexplained divergences**. Every other divergence is
    enumerated with its tracked cause, so "what does OCSF lose vs native" is a list, not a guess.
    """
    native_irs = [compile_rule(r) for r in rule_dicts]
    rewritten = [rewrite_rule_to_ocsf(ir, adapter) for ir in native_irs]
    ocsf_events = [adapter.normalize(e) for e in events]

    explained: list[dict] = []
    unexplained: list[dict] = []
    per_rule: list[dict] = []
    for ir, rw in zip(native_irs, rewritten):
        lossy = bool(rw.dropped) or rw.grade != EXACT          # faithful-exact rules must agree
        cause = ("dropped:" + ",".join(rw.dropped)) if rw.dropped else f"lossy-grade:{rw.grade}"
        n_div = 0
        for j, (e, oe) in enumerate(zip(events, ocsf_events)):
            nf, of = eval_ir(ir, e), eval_ir(rw.rule, oe)
            if nf != of:
                n_div += 1
                rec = {"rule": ir.rule_id, "event": j, "native": nf, "ocsf": of,
                       "cause": cause if lossy else "UNEXPLAINED (faithful-exact rule diverged)"}
                (explained if lossy else unexplained).append(rec)
        per_rule.append({"rule": ir.rule_id, "grade": rw.grade, "dropped": list(rw.dropped),
                         "faithful": rw.faithful, "n_diverge": n_div})

    checked = len(native_irs) * len(events)
    return {
        "vocab": {"events": adapter.vocabulary().name, "rules": adapter.vocabulary().name},
        "n_rules": len(native_irs), "n_events": len(events), "checked": checked,
        "agreements": checked - len(explained) - len(unexplained),
        "explained_divergences": explained,
        "unexplained_divergences": unexplained,
        "per_rule": per_rule,
        "attested": not unexplained,
    }
