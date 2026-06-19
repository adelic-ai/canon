# Per-TTP coverage as a layered decomposition — primitives, atoms, compositions, catch-classes

**Status:** design, 2026-06-19 (rev. 2026-06-19 — unified rule+battery atom basis, the atom-truth artifact,
the coverage join, and independence tested at the primitive grain). The rule-level content signature is
**built** (commit `6591ac1`, `main`); the primitive/atom factoring, the battery-as-atoms unification, and the
catch-class layer are **not built** (catch-class is synthcyber-gated).
**Relates to:** [[detection_ir_motif_ontology]] (the molecule = bonded gadget), [[self_validation_architecture]]
(content-addressed DAG; the recursive nested-seam / transparency knob; the Belnap independence risk §9; the
machine-checked tier on accumulation primitives), [[skos_graded_mapping_seam]] (tag / IR-content / catch-set
grounds), [[sigma_consumption_audit]] (the redundancy bracketing), [[project_detection_inversion_battery_framework]]
(battery surfaces, rules verify), [[verdict_coverage_space]] (verdicts as locations; gaps both ways),
[[project_abduction_loop_agent_design]] (uncovered anomalies → new-detection candidates),
[[project_atlas_primitive_library]] (the primitive catalog).

## The reframe

MITRE coverage is usually stated per technique — *"do we have a rule for T1003.001?"* Wrong granularity. A
technique is detected by a **set of distinct checks**, and coverage is a property of that set. The
content-aware signature work proved it concretely: the field-set key collapsed value-distinct checks into one
concept and the round fired only one — silently dropping the rest (OTRF T1003.001: 33 field-set concepts → 74
content concepts; **41 distinct detections recovered**). So per-TTP coverage is a **layered count**, and the
layer you measure at decides what "covered" and "redundant" mean.

## The layers — four, and the stack is recursive

```
primitive        count, sum, divide, log₂, multiply, compare, rank   — the irreducible arithmetic/logical leaf
   │  compose
atom / molecule  a predicate or feature                              — a Sigma clause (near-primitive) OR a
   │  bond (AND / cross-event join on a key)                            statistic like entropy (a MOLECULE of primitives)
rule             block(s) + condition                                — a composition of atoms (the authored unit)
   │  group by what they catch
catch-class      rules firing on the same instances                 — the true per-TTP variant set (ground truth)
```

- **primitive** — the irreducible op: `count`, `sum`, `divide` (→ proportion / mean = `sum ÷ count`), `log₂`,
  `multiply`, `compare`/threshold, `rank` (→ quantile/percentile). Statistics are *not* atomic: Shannon
  entropy is `histogram → divide(proportions) → log₂ → multiply → sum → negate`; MI, CFAR, conformal all
  bottom out in the same handful. This is where the **machine-checked tier** lives (round-off proofs on the
  accumulation/log primitives) and what [[project_atlas_primitive_library]] catalogs.
- **atom / molecule** — a single predicate or feature. A Sigma clause `(field, op, value)` is near-primitive
  (read field → one comparison). A statistic like `entropy(cmd_line in window)` is a **molecule** — a sub-DAG
  of primitives. The stack is therefore **recursive** (the architecture's nested-seam / transparency knob):
  entropy is *one node* from outside (black box) and an *arithmetic sub-DAG* from inside (transparent — the
  provenance and independence folds reach in).
- **rule** — a composition of atoms via blocks (AND/OR), cross-event bonds (`spawn ⋈ access on ProcessGuid`),
  and a condition. Elaboration varies; comsvcs is near-atomic, `selection and not filter` is a real composition.
- **catch-class** — rules that fire on the same labeled instances; the only layer that measures real coverage.
  Needs labeled instances (synthcyber-gated).

## One atom basis — rules and the battery are the same kind of thing

Battery detectors are **atoms in the same basis** as Sigma clauses — they just have different **ops**. There is
one atom space; the op ranges over **match-ops** (`contains`, `endswith`, `re`, `cidr`, `gt/lt`) and
**stat-ops** (`rarity`, `entropy`, `MI`, `CFAR`, `count`/`distinct`), all compositions over the same
primitives. Three consequences:

- **Stat-atoms can be multi-field / relational** (`MI(fieldA, fieldB)`, joint rarity) and **field-discovering**
  (an op with no declared field that surfaces *which* field is anomalous). Richer than single-field Sigma
  clauses. A discovered field that recurs on confirmed labels is a candidate atom promoted into the rule
  corpus — the abduction / feature-validation loop.
- **Sigma yaml is a *partial* frontend.** It expresses the atoms whose op is in its surface vocabulary: match
  clauses, plus **Sigma correlation** (`value_count`, `event_count`, `temporal`, `temporal_ordered`) for
  count/distinct/threshold/sequence. Genuinely distributional ops (entropy, MI, conformal, CFAR) have **no
  Sigma operator** — they are **IR-native**, reachable only by extending Sigma's vocabulary (custom modifiers
  like `|entropy>` / `|rare`) or a sibling frontend. Either way they lower to the **same atom IR** (the
  IR-as-spine: Sigma is one surface over part of the atom space; the IR is the superset).
- **Worked example — fan-out is two atoms, half Sigma-expressible.** Over one `(entity, time-bin)` cell the
  fan-out detector computes both `distinct = |{i : cᵢ>0}|` and `entropy = −Σ(cᵢ/N)log₂(cᵢ/N)`:
  - `distinct ≥ N` → a Sigma `value_count` correlation rule. **Sigma-expressible.**
  - `entropy ≥ θ` → no Sigma operator. **IR-native.**
  Same concept, different ops, and they are used as cross-checks of each other (`FanoutCell` carries both).

## The atom-truth artifact — the log is read once

Detection has two phases, and only one touches the data:

```
Phase A (data-bound, ONCE):  evaluate the distinct atom-set over the log  →  the ATOM-TRUTH ARTIFACT
Phase B (data-free):         every rule/composition is a fold over the artifact — the log is never re-scanned
```

The **artifact** is the log projected onto the atom basis — match-atoms as per-event truth, stat-atoms as
per-(entity, window) values. It is the load-bearing intermediate:

- **Content-addressed → a provenance node.** `artifact_id = hash(atom-set, log)`; a verdict's justification
  walks verdict → composition → **artifact** → (atoms × raw records). The artifact pins which records it
  derived from, so "how did you know?" stops at a durable object, not a re-scan.
- **CSE at the primitive grain.** Because primitives are shared sub-DAGs, the histogram for a cell is computed
  **once** and feeds `entropy` *and* `distinct` *and* `mean`. Identical atoms across rules are one node (the
  Merkle dedup property), so *more rules firing ≠ more work* — the firing-volume worry dissolves.
- **It is the warm-retention object.** raw log → artifact (kept) → verdicts (kept); the raw log can age out
  while the artifact and verdicts survive ([[retention_and_aging]] — the artifact *is* the "cells" layer made
  precise).

Not built: `eval_ir` re-touches the data per rule; `motif-rs` batches but still per-rule. The artifact is the
design target of atom factoring — corpus-free engine work (an atom-level content digest is the small addition;
today the digest is per-rule).

## The coverage join — the battery co-fires, locates uncovered, reinforces covered

The atom-truth artifact spans **both** match-atoms (the rule-known basis) and stat-atoms (a fuller basis), so
the battery is *not* blind to rule-uncovered space and is *not* a mere consumer of a rule-filtered table — it
fires in the same Phase-A pass over its own (often windowed, multi-field) atoms. Phase B **joins** the two in
the coverage space (entity × time × feature), and the join is where the value is:

```
                    a co-located match-atom fires        no match-atom at that location
stat-atom fires  →  CORROBORATE (extra witness, if        UNCOVERED area — a rule-blind anomaly →
                    independent — see below)              coverage gap OR novel-detection candidate (abduction)
no stat-atom     →  RULE-ONLY — known-bad that looks      (nothing here)
                    statistically normal; rules cover
                    what stats miss
```

The battery is an **additive** witness, never subtractive (the coverage-space wiring contract): it raises
confidence where it co-locates and surfaces gaps where it fires alone; absence of a battery signal never
demotes a rule hit.

## Independence at the primitive grain — the corrected story

Catch-set co-membership says two rules catch the **same target**; it does not say "drop one." Two checks
reaching the same target by **independent paths** are robust (survive a telemetry gap, a rename, an evasion).
But independence must be tested at the **finest (primitive) grain**, not at `(field, op)` — and the
content-addressed DAG gives it for free: two checks are independent iff their **sub-DAGs are disjoint**; a
shared primitive node is shared evidence.

This corrects an earlier, too-loose claim that "same field, different op ⇒ independent witness." It is **false**
when the ops share sub-atoms:

- `distinct` and `entropy` are **both folds over the same count-vector** (the cell histogram). They share that
  sub-DAG → they are **not** failure-independent (corrupt the counts and both are wrong). Their cross-check
  value is **complementarity** — `distinct` measures cardinality, `entropy` measures distribution-shape, and
  they can *disagree* (10 uniform values → distinct=10, entropy=3.3, both high; 10 values with one dominating →
  distinct=10 but entropy≈0). The disagreement is informative; it is **not** independent corroboration.
- **True corroboration needs disjoint sub-DAGs** — e.g. a fan-out atom on one field and a signing-anomaly atom
  on another, sharing no primitive. Belnap confidence fusion should credit only such independent witnesses; the
  DAG decides which, structurally. This closes the architecture's flagged independence question for this
  domain: independence is **decidable by sub-atom disjointness**, not assumed.

## The keys bracket redundancy — none measures it

```
key                collapses                          per-TTP effect                    redundancy
─────────────────  ─────────────────────────────────  ───────────────────────────────  ──────────
field-set          same fields (value-BLIND)          UNDER-counts variants             UPPER bound · 7.15×
content (built)    byte-identical (field+op+value)    enumerates at rule level; OVER-   LOWER bound · ~1.0×
                                                       counts equivalents
catch-set          same instances caught              the TRUE variant count            the real number
```

State per-TTP coverage as a **set bounded by these keys** until catch-set exists — content is the honest upper
bound on distinct checks (it fixed the round's recall), field-set the lower bound; truth is between and needs
the catch-set.

## The model in one picture

```
per-TTP coverage = a set of catch-classes
   each catch-class = rules (compositions) that catch the same instances
      each rule    = a composition of atoms (clauses & statistics)
         each atom = a molecule of primitives (count, sum, divide, log₂, multiply, compare, rank)
            primitives are SHARED → computed once (content-addressed CSE)
   rules and the battery are atoms in ONE basis (match-ops + stat-ops); Sigma yaml is a partial frontend
   keep >1 check per catch-class IFF their sub-DAGs are disjoint (independent witnesses — decided by the DAG)
```

## Status / buildables

- **Built — rule layer:** `CompiledRule.content_digest` + `content_signature`, in `select_detections` and the
  audit. Recall fix proven (33→74 on OTRF T1003.001).
- **Not built — atom/primitive factoring:** evaluate the distinct atom-set once → the atom-truth artifact;
  share primitives (CSE); compose data-free. Corpus-free engine work.
- **Not built — unified atom record + ops:** one `(field*, op, args)` record where op ranges over match *and*
  stat ops (the artifact's column type); a **Sigma-correlation emitter** for the count/threshold battery atoms
  that *are* expressible (so part of the battery round-trips through Sigma yaml; the distributional atoms stay
  IR-native).
- **Not built — catch-class:** the true per-TTP variant count + same-catch grouping. Gated on the
  labeled-instance generator (synthcyber).
- **Resolved by the above (once factored):** witness independence for confidence fusion — decided by sub-atom
  disjointness rather than assumed.
