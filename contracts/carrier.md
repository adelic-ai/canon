# Contract: the carrier — Belnap bilattice + the monotonicity invariant

**Status:** PINNED, 2026-05-31 (was DRAFT 2026-05-30). The value domain every fold
computes in. Pins: the four values as a `(told-true, told-false)` pair, the explicit truth
tables for all operations incl. negation, the `≤_k`-monotonicity invariant, and the
complete-lattice basis for recursive folds.

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

## The `(t, f)` model + truth tables (PIN — cross-language ground truth)

The operations are named above; this is the substance that makes them a *contract* a second
language can reproduce. Each value is a pair `(t, f)` of independent bits — `t` = "told
true", `f` = "told false". Every table below is derived from this model, so any binding
that matches the model reproduces the tables exactly (storage as enum vs two packed bits is
the binding's choice).

```
None = (0,0)   True = (1,0)   False = (0,1)   Both = (1,1)
≤_k = componentwise ≤ on (t,f)        ≤_t : t up, f down
```

**`⊕` knowledge join — accumulate evidence** (`(t,f)` componentwise OR; `None` identity,
`Both` absorbing). `True ⊕ False = Both`: disagreeing sources make a contradiction, *not*
an average.

```
⊕     | None  True  False Both        ⊗     | None  True  False Both
------+-------------------------      ------+-------------------------
None  | None  True  False Both        None  | None  None  None  None
True  | True  True  Both  Both        True  | None  True  None  True
False | False Both  False Both        False | None  None  False False
Both  | Both  Both  Both  Both        Both  | None  True  False Both
```

**`⊗` knowledge meet — consensus** (componentwise AND; `Both` identity, `None` absorbing):
above right. `True ⊗ False = None` — no agreement, no knowledge.

**`∨` truth join — OR** (`(t1∨t2, f1∧f2)`; ∃-detect) and **`∧` truth meet — AND**
(`(t1∧t2, f1∨f2)`; ∀-validate):

```
∨     | None  True  False Both        ∧     | None  True  False Both
------+-------------------------      ------+-------------------------
None  | None  True  None  True        None  | None  None  False False
True  | True  True  True  True        True  | None  True  False Both
False | None  True  False Both        False | False False False False
Both  | True  True  Both  Both        Both  | False Both  False Both
```

**`¬` negation** — swap the pair, `¬(t,f) = (f,t)`: `¬None = None`, `¬Both = Both`,
`¬True = False`, `¬False = True`. It is **`≤_k`-monotone** (swapping both components
preserves componentwise `≤`), so it satisfies the universal invariant below; it is
`≤_t`-*antitone*, as a negation should be. This is the operator temporal-negation and
∀-validate use — `"C never occurred" = ¬(∃ C)`, which under partial data correctly yields
`None`, not `True` (`../design/self_validation_architecture.md` §6).

All five operations are `≤_k`-monotone (standard bilattice result; inherited).

## Complete lattice — recursive folds have a least fixpoint (PIN)

The carrier is **finite**, hence a **complete lattice** in `≤_k` (every subset has a join
and meet, trivially by finiteness). So any `≤_k`-monotone fold has a **least fixpoint** by
Knaster–Tarski, computable by iterating from `None` (⊥) to convergence — giving recursive /
self-referential detections a well-defined value instead of diverging (the §5 backstop). A
recursive fold must be `≤_k`-monotone (it already must, by the invariant), so the lfp always
exists; no obligation beyond monotonicity.

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
