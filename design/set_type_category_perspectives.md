# Set / Type / Category — the three notions of "same rule" (SPECULATIVE)

**Status:** SPECULATIVE / exploration, 2026-06-21. A plausible-feeling correspondence, captured to think with —
**not** asserted, and **not** the formal trichotomy theorem (here "three" just means three perspectives, à la
the Set/Type/Category foundations of mathematics, borrowed for its *shape*). **Relates to:**
[[ir_vocabulary_stratification]], the catch-set grounding (`detection/catch_set.py`),
[[project_warrant_is_relational]], the resolution-axes exploration, [[project_mathabc_canon_relationship]].

## The observation

There are three ways canon asks "**are these two rules the same?**", and they line up with the Set / Type /
Category perspectives on mathematical sameness:

- **Set ↔ `clause_set`.** A rule *as a set of conditions*. Sameness = same elements. The lattice's whole
  algebra — subset (⊆), intersection (∩) — *is* set algebra; that's what yields "broader / overlaps /
  neighborhood." **Extensional**: a rule *is* its set of clauses.
- **Type ↔ `content_digest`.** A rule *as its construction* — the syntax tree, how the atoms are wired. Same
  elements built differently (OR vs AND, different filters) → *different here*. **Intensional**: identity by
  how it's built, not just what it contains.
- **Category ↔ `catch-set` / behavior.** A rule *as its mapping* (events → fire / no-fire), known only by its
  morphisms — how it relates to events and to other rules (co-catch). Sameness = **behavioral / observational
  equivalence**: you know the object by its arrows, not its insides.

## The axes — the load-bearing part

Set and Category are **orthogonal axes, not points on a line.** They disagree in two independent directions,
which are exactly `ground_lattice`'s two off-diagonals:

- **Set-same but Behavior-different** = **over-grouping** (svchost pair: identical clause-set, *opposite*
  catches — same search, different filters).
- **Behavior-same but Set-different** = **under-grouping** (comsvcs pair: totally different clauses
  — `CallTrace` vs `StartModule` — *same* catch).

So `ground_lattice` is literally **a map of the disagreement between the Set axis and the Category axis.**

**Type is the meet** — the finest of the three. `content_digest`-same ⟹ `clause_set`-same **and**
behavior-same (identical construction forces both). It's the single corner where the two axes coincide and no
disagreement is possible. (This is why an earlier "fix" that swapped the Set-exact for the Type-exact inside
the grounding was wrong: Type is the corner with *no gap*, so it collapsed the over-group axis the grounding
exists to keep open. You measure the Set⊥Category gap with the Set view, never the Type meet.)

```
                 Type  (content_digest — intensional, finest)
                /    \         content_digest-same ⟹ both below
              ⊆        ⊆        (forgetful: drop construction, keep …)
            Set        Category
       (clause_set)   (catch-set)
       extensional     behavioral      Set ∥ Category  (incomparable — the two axes)
                \    /
                 ⊤  (trivial: "all rules the same")
```

## The "wiring" — is it S3 / a symmetry? (honest answer: no, but there's structure)

It is **not** the symmetric group S₃ — the three are *not* interchangeable. Type is **distinguished** (strictly
finer; it implies the other two), and Set ∥ Category are **incomparable** (neither implies the other — that's
the whole point of the two off-diagonals). A symmetry would require permuting the three freely; you can't,
because Type is special and the other two are an antichain. So no group acts symmetrically on them.

What there *is*: a **refinement partial order** (the small lattice drawn above) with **forgetful maps** —
Type → Set *forgets construction while keeping extension*; Type → Category *forgets construction while keeping
behavior*. Those are directed (information-losing), not symmetric. So the "transformation" intuition is right
in spirit — there are maps between the perspectives — but they're a forgetful refinement structure, not a
symmetry group.

One place an S₃-flavored thing *does* live: the **foundations themselves**. Set, Type, and Category as
foundations of mathematics form a triangle of mutual *inter-translations* (sets-as-types, categorical-semantics-
of-type-theory, categories-built-from-sets) — closer to a 3-cycle, more symmetric. Our *instance* (the three
rule-equivalences) breaks that symmetry by making Type the meet. So if there's a symmetric structure to chase,
it's upstream in the foundations, not in this instance.

## Why it's more than a cute analogy — perspective ↔ intent

It tells you *which perspective to use for which job* (the order-of-operations / intent question):

- **Set** — for the lattice's *relationships and neighborhoods* (intersection, subsumption). "The intent isn't
  dedup; it's the intersections." Set algebra is exactly that.
- **Type** — narrowly, for *true duplicate detection* (byte-identical logic).
- **Category / behavior** — as the *ground truth* you validate against (catch-set).

And the **bugs live in the gaps between the axes** — over-grouping and under-grouping are precisely where the
Set perspective and the Category perspective disagree. That's not a defect of any one perspective; it's why you
need more than one, and why grounding (the Set↔Category comparison) is a distinct, irreducible step.

## Honest caveats

- This is an **instance** of the Set/Type/Category *shape*, not the foundations themselves (which ground all of
  mathematics). "Three perspectives," not the trichotomy theorem.
- The legs aren't equally tight. **Set ↔ clause_set** (set algebra) and **Category ↔ behavior**
  (observational/coalgebraic equivalence) are near-literal. **Type ↔ content_digest** is the loosest leg —
  intensional/syntactic identity, *type-theory-flavored* (construction-as-identity, intensional equality) but
  not literally type theory.
- Plausible, not proven. The value is the *map of where structure and behavior part ways*; the foundational
  dress is a lens, to be dropped the moment it stops paying for itself.
