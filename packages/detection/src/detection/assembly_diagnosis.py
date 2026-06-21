"""Assembly-level non-fire diagnosis — WHY a rule that claims a technique misses a labeled instance.

A rule that doesn't catch an instance it claims has a fault *somewhere*. The naive read is "which atom
failed"; the better read (and the one this implements) is **assembly-level localization using atom reuse as
an exoneration oracle**:

- An atom that appears across many curated rules is a *vouched discriminator* — if it doesn't match this
  event, that's a real **variant difference** (the rule targets a different LSASS-dump variant), not a bug.
  A typo in a vouched atom would have broken its sibling rules too, so it'd already be caught.
- A **rule-unique** atom that misses is the one-character-typo hiding place — nobody else vouches for it.

So the fault localizes to the **assembly** (the composition/condition, or a filter that excludes) or to an
*unvouched* rule-unique atom — never to the shared atoms, which fire fine in their siblings. This is the
corroboration principle (independent witnesses) turned inward onto fault localization in the rule itself.

See ``design/ir_vocabulary_stratification.md`` (closed predicates = vouched primitives) and the fidelity /
catch-set threads. Scope: structural + single-instance — it explains one silent rule against one labeled event.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from detection.atom_index import block_polarities, clause_atom_id
from detection.rule_ir import compile_rule, eval_ir
from detection.sigma_eval import is_evaluable


def build_atom_reuse(rules: list[dict]) -> dict[str, int]:
    """``{atom_id: number of distinct rules whose POSITIVE selection contains it}`` over the corpus — the reuse
    count that vouches an atom. >1 ⇒ used across multiple curated rules (a known-good discriminator); ==1 ⇒
    rule-unique (unvouched, the typo/over-specific-marker candidate)."""
    count: dict[str, int] = defaultdict(int)
    for r in rules:
        if not isinstance(r, dict) or not is_evaluable(r):
            continue
        try:
            ir = compile_rule(r)
        except Exception:
            continue
        pol = block_polarities(ir)
        seen: set[str] = set()
        for b in ir.blocks:
            if b.kind == "keyword" or 1 not in pol.get(b.name, {1}):    # positive field-map blocks only
                continue
            for m in b.maps:
                for c in m:
                    seen.add(clause_atom_id(c))
        for aid in seen:
            count[aid] += 1
    return dict(count)


def _positive_atoms(ir):
    """The ``(clause, block_name)`` positive-selection atoms (filter/exclusion + keyword blocks excluded)."""
    pol = block_polarities(ir)
    out = []
    for b in ir.blocks:
        if b.kind == "keyword" or 1 not in pol.get(b.name, {1}):
            continue
        for m in b.maps:
            for c in m:
                out.append((c, b.name))
    return out


def diagnose_silent_rule(rule: dict, event: dict, atom_reuse: dict[str, int]) -> dict:
    """Localize why ``rule`` (which claims a technique) does not fire on ``event``. ``atom_reuse`` is the
    corpus reuse map from :func:`build_atom_reuse`. Returns the fault and the supporting decomposition.

    fault ∈ {
      ``fires``            — it actually fired (caller usually filters these out),
      ``keyword-miss``     — a keyword-only rule whose needle isn't in any field value (keyword blocks read
                             EVERY field, so this is a value miss on a populated event, NOT missing-telemetry),
      ``wrong-channel``    — the rule reads NONE of this event's fields (missing-telemetry, not a logic fault),
      ``filter-excluded``  — positive logic matches but a filter/exclusion block matches → allowlisted,
      ``composition-gap``  — every positive atom matches in isolation, yet the rule doesn't fire (the
                             condition's block-combination / quantifier is unsatisfied — an ASSEMBLY fault),
      ``variant-miss``     — a present-field atom's value differs and that atom is VOUCHED (reused) → the rule
                             targets a different variant (legitimate non-fire),
      ``unvouched-miss``   — a present-field atom's value differs and the atom is RULE-UNIQUE. The candidate
                             POOL for bugs, but on real data MOSTLY legitimate variant-specific discriminators
                             (hacktool lists, debug-DLL traces, access masks). Rule-uniqueness is necessary
                             but far from sufficient for "bug"; the real bug signal is NEAR-MISS (the value is
                             one edit from a value PRESENT in the event) — an edit-distance filter on top,

      ``field-absent-gap`` — needs a field this event lacks though some fields are present (partial channel).
    }
    """
    ir = compile_rule(rule)
    fires = eval_ir(ir, event)
    pos = _positive_atoms(ir)
    pol = block_polarities(ir)

    # An atom HITS only if its field is PRESENT and matches. `Clause.matches` reads `event.get(field, "")`,
    # so an empty-pattern clause (`|contains: ""`, `|re: ".*"`) matches an ABSENT field — a ghost match that
    # must not count as present/matched. `hit` is the single source of truth used everywhere below.
    def hit(c) -> bool:
        return c.field in event and c.matches(event)

    present = [(c, bn) for c, bn in pos if c.field in event]
    missed = [(c, bn) for c, bn in pos if not hit(c)]                     # absent OR present-but-value-wrong
    missed_present = [(c, bn) for c, bn in missed if c.field in event]    # value-miss (field there, value wrong)
    has_keyword = any(b.kind == "keyword" and 1 in pol.get(b.name, {1}) for b in ir.blocks)
    filters_hit = [b.name for b in ir.blocks
                   if -1 in pol.get(b.name, set()) and b.matches(event)]

    def vouched(c) -> bool:
        return atom_reuse.get(clause_atom_id(c), 0) > 1

    unvouched = [(c, bn) for c, bn in missed_present if not vouched(c)]

    if fires:
        fault = "fires"
    elif not pos and has_keyword and event:
        fault = "keyword-miss"                   # keyword blocks read EVERY field → not wrong-channel
    elif not present:
        fault = "wrong-channel"                  # reads none of this event's fields → not a logic fault
    elif not missed and filters_hit:
        fault = "filter-excluded"
    elif not missed:
        fault = "composition-gap"                # all atoms match, condition still unsatisfied → assembly
    elif missed_present:
        fault = "unvouched-miss" if unvouched else "variant-miss"
    else:
        fault = "field-absent-gap"               # missed atoms are all field-absent, some fields present

    def show(c, bn):
        aid = clause_atom_id(c)
        return {"block": bn, "atom": c.as_tuple(), "reuse": atom_reuse.get(aid, 0)}

    return {
        "rule_id": ir.rule_id,
        "fires": fires,
        "fault": fault,
        "exonerated": [show(c, bn) for c, bn in present if hit(c)],            # field present AND matches
        "value_miss": [show(c, bn) for c, bn in missed_present],               # field present, value wrong
        "suspect_atoms": [show(c, bn) for c, bn in unvouched],                 # rule-unique misses (bug locus)
        "filters_hit": filters_hit,
    }


def diagnose_silent_rules(rules_for_technique: list[dict], event: dict,
                          atom_reuse: dict[str, int]) -> dict:
    """Diagnose every rule in ``rules_for_technique`` against ``event`` and tally the faults. The
    ``composition-gap`` and ``unvouched-miss`` rows are the actionable ones (assembly faults / candidate
    bugs); ``wrong-channel`` and ``variant-miss`` are honest non-faults (right rule, wrong event)."""
    diags = [diagnose_silent_rule(r, event, atom_reuse) for r in rules_for_technique
             if isinstance(r, dict) and is_evaluable(r)]
    by_fault: dict[str, list] = defaultdict(list)
    for d in diags:
        by_fault[d["fault"]].append(d["rule_id"])
    return {
        "n_rules": len(diags),
        "fault_tally": dict(Counter(d["fault"] for d in diags)),
        "by_fault": {k: sorted(v) for k, v in by_fault.items()},
        "diagnoses": diags,
    }
