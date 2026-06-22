# Three notions of "the same rule" — and why detection needs all three

**Status:** design note, 2026-06-21. Describes the actual structure already in the code
(`clause_set` / `content_digest` / `catch_set`); not speculative. **Relates to:**
[[ir_vocabulary_stratification]], the catch-set grounding (`detection/catch_set.py`), the rule lattice
(`detection/rule_lattice.py`), [[project_warrant_is_relational]].

## Three different ways to say two rules are "the same"

Each is a real, distinct equivalence relation on rules, and they do **not** coincide:

1. **Same conditions** — `clause_set`. They search for the same things: the set of `(field, predicate, value)`
   atoms in their *positive* selection. This is what the lattice compares with subset (⊆) and intersection (∩)
   to get "broader / narrower / overlaps / neighborhood." **Blind to filters and to how the conditions are
   wired** (AND vs OR).
2. **Same construction** — `content_digest`. Byte-for-byte identical logic: same atoms, same filters, same
   condition wiring. The strictest. Two rules with the same conditions but different filters — or OR vs AND —
   differ here.
3. **Same behavior** — `catch-set`. They fire on the same labeled instances. The only one about what a rule
   *does*, not what it *says*. Needs real attack data to compute.

## They're genuinely different — two failure cases prove it

- **Same conditions, different behavior** (*over-grouping*): two `svchost.exe` rules with identical positive
  conditions but different filters (one excludes "in System32," the other excludes "parent = services.exe")
  catch *opposite* events. `clause_set` says "same"; behavior says "different."
- **Different conditions, same behavior** (*under-grouping*): the comsvcs pair — `CallTrace contains comsvcs`
  vs `StartModule endswith comsvcs`, totally different conditions — catch the *same* LSASS dump. `clause_set`
  says "unrelated"; behavior says "synonyms."

## The structure — a refinement order

- **Same-construction is the finest.** `content_digest`-equal ⟹ same conditions **and** same behavior
  (identical logic forces both). It implies the other two.
- **Same-conditions and same-behavior are incomparable.** Neither implies the other — the two failure cases
  above are exactly the two directions they come apart. They are orthogonal.

```
                 same construction  (content_digest — finest; implies both below)
                /                \
        same conditions      same behavior
          (clause_set)        (catch-set)
       what the rule SAYS    what the rule DOES      ← incomparable; this gap is where the bugs live
```

## `ground_lattice` is the map of where "says" and "does" disagree

It cross-tabs the **structural** relation (same-conditions, via `clause_set`) against the **behavioral**
relation (same-behavior, via `catch-set`) for every pair of rules, and surfaces the two off-diagonals:
**over-grouped** (conditions say same, behavior says different) and **under-grouped** (behavior says same,
conditions say different). This comparison is **irreducible** — neither view alone tells you what the other
does, so you can't drop it.

(Note: `ground_lattice` uses `clause_set` for its structural axis *on purpose* — the lossy "same-conditions"
view is exactly what over-grouping exposes. Using `content_digest` there would make over-grouping impossible
to see, since identical construction can't behave differently.)

## SKOS and FCA operate on the structural axis — at different resolutions

The "same conditions" side isn't one thing — it's a ladder of structural keys, coarse to fine, and SKOS and
FCA are operations that pick a rung:

- **FCA — field-set key (coarsest, value-blind).** Groups rules into concepts by *which fields* they read,
  ignoring values. Maximally over-collapsing: it folded 32 distinct macOS detections into one "concept" because
  they read the same fields.
- **SKOS — `clause_set` (finer).** The lattice's graded relations are built on `(field, predicate, value)`
  atoms: subset → broad/narrow, intersection → related, with `content_digest` gating exact. Still positive-only,
  so still filter/keyword-blind.
- **`content_digest` (finest).** Everything — the true-duplicate key.

So `FCA field-set → clause_set / SKOS → content_digest` is one ladder, coarse → fine, all on the structural
("says") axis. FCA adds a concept hierarchy; SKOS adds the graded order; both are structure-over-conditions.

Two consequences:
- **Coarser key ⟹ more over-grouping.** FCA over-collapses most, SKOS less, `content_digest` none. The
  over-collapsing canon kept hitting (32→1; filter-different rules called "exact") is the structural axis
  over-claiming at whatever resolution was chosen.
- **All of it is still "says," so all of it is grounded by catch-set.** SKOS concepts, FCA concepts, exact
  classes — none tell you what a rule *does*. `catch-set` (behavior) is the orthogonal corrective for every rung.

(Same ladder as the detection resolution axis `tag → FCA field-set → content_signature → catch-set`: pick a
structural resolution, then ground it against behavior.)

## Which view for which job

- **Same-conditions (`clause_set`)** — the lattice's relationships and neighborhoods (the whole graded
  structure: subsumption, overlap). The intent here isn't dedup; it's the intersections — and a set is what you
  do that math on.
- **Same-construction (`content_digest`)** — true duplicate detection, and the structure-aware `exactMatch`
  edges in the lattice (so OR-vs-AND with the same conditions isn't called a synonym).
- **Same-behavior (`catch-set`)** — the ground truth you validate the other two against.

## The one durable point

The bugs live in the gap between **what a rule says** and **what a rule does.** That's why you can't pick a
single view: the structural one (`clause_set`) scales and gives you the relationships; the behavioral one
(`catch-set`) is the truth; and the comparison between them (`ground_lattice`) is the irreducible step that
catches where they part.
