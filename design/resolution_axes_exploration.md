# Resolution axes — what we built to sharpen Sigma, and what's left

**Status:** EXPLORATION, 2026-06-21. Not a committed spec — a reflection that names a frame
already implicit across the detection package. Rendered companion: `web/resolution_axes.html`
(the seed question verbatim beside its developed answer). Relates to:
[[sigma_treatment_pipeline]] (the manifest that makes instance-ness explicit),
[[warrant_is_relational]] (the principle this applies to our own work),
[[skos_graded_mapping_seam]], [[full_corpus_dedup_pass]] (the content_digest gap),
[[self_validation_architecture]] (the Belnap carrier).

## The seed

Observation that prompted this: *a lot of canon's Sigma work is an instance* — the structure we
extract depends on the datasets we ran AND on the constructions we built to let Belnap/SKOS/FCA
parse the data at higher resolution. Two questions fall out: what are all the constructions built
for this purpose, and what else can raise resolution?

## "It's an instance" = warrant-is-relational, turned inward

The treated Sigma corpus is a **derived result**, warranted only relative to its inputs
`(corpus@cid, code@sha, labels)`. That is exactly [[warrant_is_relational]] applied to our own
output, not a defect. The construction that makes the instance-ness explicit and *measurable* is
the treatment manifest (`detection/treatment_pipeline.py`): pin the producing state, then **diff
two result-CIDs when an input is swapped**. That diff IS the measurement of "how much is instance
vs stable structure." So managing instance-contingency and increasing resolution are the same
activity from two sides.

Define **resolution** = the power to distinguish things genuinely different and to merge things
genuinely the same. Low resolution = over-collapse (FCA folding 32 macOS detections into 1) or
under-distinction.

## The five axes (each: lossy → fine, claim → structure → behavior)

1. **What does a rule detect?** `tag → FCA concept-key → IR content_signature → catch-set`
   - tag (`attack.tXXXX`): the author's claim (79 claim T1003.001, 2 catch).
   - FCA concept-key (`audit.py`): field-SET, value-blind — a resolution **floor**, over-collapses.
   - IR content_signature (`rule_ir.py`): clauses + values, corpus-free.
   - catch-set (`catch_set.py`): what's actually caught, corpus-grounded — highest, data-contingent.

2. **How do two rules relate?** `binary dedup → SKOS lattice → tightness → behavioral co-catch`
   - `rule_lattice.py`: exact/close/broad/narrow/related — a navigable order, not a collapse.
   - tightness (IDF-weighted Jaccard): continuous; IDF = the entropy-analog.
   - `atom_implication.py`: the relation at atom altitude.
   - `ground_lattice` (`catch_set.py`): the **arbiter** — cross-tabs structural × behavioral, locating
     where structure under/over-resolves (finding: behavioral synonyms are structurally `related`,
     not `exact` → dedup under-resolves).

3. **The carrier (state of knowledge).** `boolean → Belnap four-valued` — None ≠ True ≠ False ≠ Both;
   the resolution SQL-`NULL`→`False` destroys. (`provenance` carrier.)

4. **Cross-schema mapping fidelity.** `exact-or-nothing → SKOS-graded + load-bearingness gate`
   (`vocab.py`/`ocsf_*.py`): grade the mapping, gate demotion on whether the difference is
   load-bearing on *this* detection.

5. **Why did a rule miss?** (negative space) `silent → typed cause → assembly-level` —
   `fidelity.py` (missing-telemetry / logic-gap / allowlist) → `assembly_diagnosis.py`.

## What else can raise resolution (priority)

1. **Filter-aware + value-aware structural keys** — the queued `content_digest`. FCA is value-blind,
   `clause_set` is positive-only (filter-blind); both verified to over-group ([[full_corpus_dedup_pass]]).
   Raises axis-1/2 resolution with NO new data — cleanest next.
2. **Catch-profile, not catch-set** — record *why* each instance fired (the discriminator), not just
   *which*. Resolves same-set/different-mechanism (comsvcs: CallTrace vs StartModule). `ground_lattice.why()`
   already half-computes it.
3. **Cross-corpus ablation** — run the treatment over N corpora, diff result-CIDs. Stable-across-corpora
   = structure; moves = instance. Quantifies the instance-ness directly.
4. **Don't collapse the two verdict axes** — Belnap (discrete) and confidence (log-odds) orthogonal;
   keep both per node.

## The honest cap — NOT a construction

Behavioral resolution is bounded by **data shape**, not machinery. Atomic-red-team captures are
pure-attack: no benign population (can't resolve precision/FP), cross-channel-disjoint (can't resolve
same-channel rule disagreement). This is the wall both the catch-set lane and the fan-out battery hit
(2026-06-20). You cannot construct past thin data — the next jump needs differently-shaped data
(benign background + same-channel variation; `bots-v3` the candidate), not more parsing of isolated
captures. See [[project-catch-set-grounding]].

## One line

Resolution rises claim → structure → behavior across five axes, but behavior is the least portable —
which is *why* the treated corpus is an instance. Sharpen the portable structural keys where no data
is needed (`content_digest`); quantify the instance-ness where it is (cross-corpus ablation).
