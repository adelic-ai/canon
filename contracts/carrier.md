# Contract: the carrier — Belnap bilattice + the monotonicity invariant

**Status:** DRAFT, 2026-05-30. The value domain every fold computes in.

Every fold computes in **Belnap's four-valued bilattice** `FOUR`:

```
values:  None  (no information — bottom of knowledge)
         True
         False
         Both  (contradictory information — top of knowledge)
```

with **two distinct partial orders**:

- **knowledge order `≤_k`**:  `None ≤ {True, False} ≤ Both`
- **truth order `≤_t`**:      `False ≤ {None, Both} ≤ True`

and **four operations** (meet/join in each order) — they must be named distinctly in every
binding because mixing them is a subtle, real bug:

- knowledge: `⊗` (consensus / meet) and `⊕` (gullibility / join)
- truth:     `∧` (min) and `∨` (max), with `¬` swapping True/False and fixing None/Both

## The universal invariant

> **Every fold is `≤_k`-monotone.** Combining evidence may only move *up* the knowledge
> order (`None → {T,F} → Both`); a fold can never *lose* knowledge.

This is the formal statement of **"absence of evidence ≠ evidence of absence"** (`None` is
bottom; it is never silently promoted to `False`), and it is the formal statement of the
architecture's acceptance test — *"add concern N without touching concern M"* is exactly
"each fold is a `≤_k`-monotone map." It is **CI-checkable**: every fold ships a property
test that feeds `None`/`Both` and asserts no knowledge-order violation. A fold that cannot
be written `≤_k`-monotone is rejected and re-cut.

The **truth order `≤_t`** is used *only* at the final detect/validate projection, where
non-monotonicity is allowed because it is terminal, not propagated.

## Lifting — the carrier is the type the other folds compute in

Partiality is not a separate pass; it is the *codomain* of every other fold:

- confidence (LLR / log-odds) → `LogOdds | None`
- temporal match → `Matched | NotMatched | NotYetObservable(None) | Conflicting(Both)`
- guarantee tier → carries `absent` as `None`

As long as each operator is `≤_k`-monotone, the partiality guarantee is *preserved by
construction* — the partiality "fold" needs no traversal of its own; it constrains the
*type* of the others.

## `Both` and `None` are first-class signals, not noise

- **`Both`** (an ∃-detect path and a ∀-validate path disagree) is wired to the
  self-falsification machinery: it is the soundness alarm, *and* a rigor-escalation trigger
  (route the subtask to a deeper/verified joint). Never average `Both` into a scalar — it
  is *not* "confidence 0.5"; it is two confident contradictory sources.
- **`None`** carries *which* input was missing as structural provenance (the DAG is
  content-addressed, so a missing input is a known, named gap): "no Sysmon 4688 in window",
  not a bare bottom symbol.

## Don't

- Don't collapse `None`→`False` at any internal boundary (the SQL-`NULL` `WHERE` bug —
  "we didn't look" becomes "we looked and it's clean"). Collapse only at a clearly-labeled
  final decision with an explicit policy (`absent ⇒ fail-closed` vs `absent ⇒
  inconclusive`).
- Don't borrow Belnap *as a non-monotonic entailment relation* — borrow the **monotone
  bilattice algebra** only.
- Don't carry graded belief and knowledge value as one number — a node can be
  high-confidence-True *or* `Both`; these are orthogonal axes, both recorded per node.
