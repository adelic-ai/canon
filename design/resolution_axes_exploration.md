# Resolution axes — what we built to sharpen Sigma, and what's left

**Status:** EXPLORATION, 2026-06-21. Not a committed spec — a reflection that names a frame
already implicit across the detection package. Rendered companion: `web/rules/resolution_axes.html`
(the seed question verbatim beside its developed answer). Relates to:
[sigma_treatment_pipeline](sigma_treatment_pipeline.md) (the manifest that makes instance-ness explicit),
[warrant_is_relational](warrant_is_relational.md) (the principle this applies to our own work),
[skos_graded_mapping_seam](skos_graded_mapping_seam.md), [full_corpus_dedup_pass](full_corpus_dedup_pass.md) (the content_digest gap),
[self_validation_architecture](self_validation_architecture.md) (the Belnap carrier).

## The seed

Observation that prompted this: *a lot of canon's Sigma work is an instance* — the structure we
extract depends on the datasets we ran AND on the constructions we built to let Belnap/SKOS/FCA
parse the data at higher resolution. Two questions fall out: what are all the constructions built
for this purpose, and what else can raise resolution?

## "It's an instance" = warrant-is-relational, turned inward

The treated Sigma corpus is a **derived result**, warranted only relative to its inputs
`(corpus@cid, code@sha, labels)`. That is exactly [warrant_is_relational](warrant_is_relational.md) applied to our own
output, not a defect. The construction that makes the instance-ness explicit and *measurable* is
the treatment manifest (`detection/treatment_pipeline.py`): pin the producing state, then **diff
two result-CIDs when an input is swapped**. That diff IS the measurement of "how much is instance
vs stable structure." So managing instance-contingency and increasing resolution are the same
activity from two sides.

**The precise cut (sharpening the headline — not *all* the treatment is an instance).** The
STRUCTURAL half — `content_signature`, the lattice structure, the Belnap carrier, the mapping
grades — is **corpus-free, therefore portable**; it does not move with the data. Only the
**BEHAVIORAL half** (catch-set, fidelity) is the instance: corpus-bound, capped by data shape.
That gives the actionable line — **machinery sharpens the portable structural half** (invest
freely, no data needed: `content_digest`); **only data moves the data-bound behavioral half** (the
actual instance: more/better-shaped corpora). The priority list below already respects this split;
naming it up front is the refinement. (Independently confirmed: the main instance's bots-v3
two-sided run is the first test of the data-bound half — see [detection/catch_set.py](../packages/detection/src/detection/catch_set.py).)

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

## What else can raise resolution (priority — ranked by THESIS-LEVERAGE, not cost)

Ranking axis matters: an earlier draft put `content_digest` first because it is *cheap and
needs no data* — but that conflated cost with importance. Ranked by what actually advances the
warrant/independence thesis (cost noted separately):

1. **Cross-corpus ablation** — run the treatment over N *genuinely different* corpora (different
   orgs/sources), diff result-CIDs. Stable-across-corpora = portable structure; moves = the
   instance. This is the only move on the list that buys **real independence** — different data,
   not two agents sharing a driver (the common-mode trap; convergence-of-instances is NOT
   independence). So it is both the empirical measure of instance-ness AND the external-validity
   test of whether any of this frame is *right* vs merely internally tidy. Highest leverage.
2. **Catch-profile, not catch-set** — record *why* each instance fired (the discriminator), not
   just *which*. Makes corroboration-by-independence **measurable**: same-discriminator co-catch =
   synonym; different-discriminator co-catch = independent witnesses (comsvcs CallTrace vs
   StartModule). Advances the verdict thesis directly. Behavioral → data-bound (an instance, not a
   free win). `ground_lattice.why()` already half-computes it. Complements #1: catch-profile makes
   behavioral resolution *richer*, ablation tests how much *generalizes*.
3. **Filter-aware + value-aware structural keys** — the queued `content_digest`. FCA is value-blind,
   `clause_set` is positive-only (filter-blind); both verified to over-group ([full_corpus_dedup_pass](full_corpus_dedup_pass.md)).
   **Cheap and needs no data — but low thesis-leverage**: it polishes the structural *proxy* that
   behavioral grounding (catch-set) is supposed to override anyway. Its real payoff is the SigmaHQ
   clean-dedup contribution path, not load-bearing resolution. Cheap ≠ important. (It *does* remain
   the only resolution lever in the no-data regime — where most of the corpus lives — so not zero.)
4. **Don't collapse the two verdict axes** — Belnap (discrete) and confidence (log-odds) orthogonal;
   keep both per node. A **maintained invariant**, already true in the justified-verdict substrate —
   "don't regress," not a new frontier. Lowest as an initiative.

The independence lesson cuts a specific way: it **demotes** convergence-of-instances as evidence
and **promotes** cross-corpus ablation — the one move here that gets independence from *different
data* rather than different puppets. #1 and #2 pair with the data work (bots-v3): the data is what
gives catch-profile anything to profile, and ablation is the test of whether the bots result is an
instance or a structure.

## The honest cap — NOT a construction

Behavioral resolution is bounded by **data shape**, not machinery. Atomic-red-team captures are
pure-attack: no benign population (can't resolve precision/FP), cross-channel-disjoint (can't resolve
same-channel rule disagreement). This is the wall both the catch-set lane and the fan-out battery hit
(2026-06-20). You cannot construct past thin data — the next jump needs differently-shaped data
(benign background + same-channel variation; `bots-v3` the candidate), not more parsing of isolated
captures. See [detection/catch_set.py](../packages/detection/src/detection/catch_set.py).

## One line

Resolution rises claim → structure → behavior across five axes. The structural half is portable
(corpus-free); only the behavioral half is the instance (data-bound). So machinery alone sharpens
the structural half (`content_digest`, no data needed) — the behavioral half moves only with
better-shaped data (cross-corpus ablation quantifies it; bots-v3 is the first test of the cap).
