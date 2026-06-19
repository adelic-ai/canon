# OCSF ingest normalization — an *optional* data-plane waist

**Status:** design, not built. Branch `design/ocsf-ingest-normalization`.
**Relates to:** [[engine_workspace_boundary]] (vocab + adapters are workspace config),
[[skos_graded_mapping_seam]] (the Sigma↔OCSF map is a graded, lossy edge),
[[verdict_coverage_space]] (missing-attribute = NONE, not FALSE).

## What this slice is — and is not

This is the **data plane**: turn heterogeneous source telemetry (ps, eslogger, Sysmon,
CloudTrail, …) into one normalized event vocabulary so detections run against a single
shape regardless of origin. It is the principled replacement for the hand-rolled
`comm→Image, args→CommandLine` adapter the macOS `ps` test exposed.

It is **not** the concept key. Grouping rules by "what they detect" lives in a separate
thread (content-aware IR signature → catch-set co-membership). OCSF normalizes the *fields
a rule reads*, not *what the rule detects*: 32 keyword rules all read
`actor.process.cmd_line` and still collapse under a field-set key. OCSF's own ATT&CK
mapping is the same tag-claim the fidelity numbers falsified (79 claim / 2 catch). Keep the
two threads separate; this doc is only the data plane.

## The core requirement: normalization is OFF-able

OCSF is a **pipeline stage with identity as a valid setting**, never a mandatory gate.
Forcing lossy normalization where it isn't needed destroys signal. The cases where you
turn it **off** and run native:

- **Single-source, native-rule** (the OTRF T1003.001 round today): Sysmon data + Sysmon-
  targeted Sigma already share a vocabulary. Inserting OCSF is two lossy hops
  (Sysmon→OCSF→rule-rewritten-to-OCSF) where zero were needed, plus per-event cost.
- **Fidelity / forensic-exact / adversarial-robustness** (the `machine_checked` tier):
  you want the raw values, not a re-encoded normalized view. Normalization is an
  abstraction that can *hide* the minute, in-tolerance manipulation that tier exists to
  catch.
- **A load-bearing field with no clean OCSF home**: if a detection keys on a field OCSF
  can only represent as `broad`/`unmapped`, normalizing is a net loss for *that* rule.
- **No adapter yet**: a new source with no OCSF map should still run native rules
  immediately, not block on building the map.

Cases where you turn it **on**: multi-source correlation (the actual point — join
ps + eslogger + Sysmon + CloudTrail in one vocab), cross-source rule reuse (one rule fires
against any normalized source), the enterprise heterogeneous-retention vision.

So the toggle is not cosmetic. It is: **which vocabulary does this run operate in?**

## The coherence constraint (why it's a vocabulary *pair*)

Events and rules must agree on vocabulary, or every match is a silent NONE. You cannot run
OCSF-rewritten rules against native events — the field names don't line up. So the toggle
selects a **coherent (events-vocab, rules-vocab) pair**:

- `native`  — source events as-ingested  ⋈  rules in their native logsource vocab.
- `ocsf`    — source→OCSF events          ⋈  rules through the Sigma→OCSF pipeline.

The engine itself is unchanged either way: the IR keys on field strings; it fires whatever
field names are present against whatever the rules name. Only the *pairing* changes. That
is the clean seam that makes OCSF optional without a second engine.

## OCSF is the easy plug, not the only one

OCSF is the **off-the-shelf, standard** normalization: broad coverage, a maintained schema,
a ready pySigma pipeline — the cheap route to a cross-source join, lossy on the edges. It is
one *target vocabulary* plugged into the seam above, not the seam itself. The full spectrum
is three points, coarsest-but-exact to convenient-but-lossy to precise-but-handmade:

1. **`native`** — zero hops, exact, but single-vocabulary (no cross-source join).
2. **`ocsf`** — the easy default *when you want the join and don't need field-exactness*.
   Standard, broad, lossy; you accept the grades it gives.
3. **`bespoke`** — a hand-wired, carefully graded mapping for the specific fields that
   matter, used *when desired*: when OCSF's grade is `broad`/lossy on a **load-bearing**
   field, you wire that field precisely instead. Higher fidelity, more work, scoped to where
   it pays.

All three are the *same* vocabulary-pair seam with a graded map — `native` is the identity
map, `ocsf` is the off-the-shelf map, `bespoke` is a precision map (often a *refinement* of
the OCSF map on just the load-bearing fields, not a full from-scratch rewrite). The grade is
what tells you which you need: OCSF until `.why()` shows a lossy edge on a field this
detection leans on, then bespoke for that edge. So "wire up something carefully when desired"
is a first-class mode, not a fork off the design — it's the same plug, tightened where it
counts.

## Granularity of the switch

Not just one global flag. Three levels, coarsest to finest:

1. **Per-run / per-workspace** (default): `vocabulary: native | ocsf` in the workspace
   manifest ([[engine_workspace_boundary]]), with the adapter/pipeline pin.
2. **Per-source**: normalize the sources that benefit (multi-source join), leave a native
   source native. The round can fire against a *mixed* fleet only after a common target
   vocab is chosen — mixing is what OCSF buys, so per-source-off means "this source opts
   out of the join."
3. **Per-detection / per-field, informed by loss**: where the Sigma→OCSF map for a rule's
   fields is `exactMatch`, normalize freely; where it is `broad`/lossy on a **load-bearing**
   field, prefer native (or fire native as a fallback and flag the demotion). This ties the
   on/off decision to the *same load-bearingness gate* as [[skos_graded_mapping_seam]] — the
   system can tell you where normalization is safe instead of you guessing.

## Graded, lossy, validated — not assumed faithful

The Sigma↔OCSF map is a graded edge, same discipline as everywhere else:

- Each field mapping carries a SKOS grade (`exact`/`close`/`broad`/`narrow`) with a
  callable `.why()` (sub-scores, definitional pointers, the OCSF attribute path).
- A rule field with **no** populated OCSF attribute in *this* source's events is a NONE
  (missing telemetry), made visible in a shared vocabulary — which is strictly better than
  hiding it in per-source field-name mismatches. This is the coverage-space NONE, not a
  penalty.
- **Faithfulness gate (mirrors `attest_rust_agreement`):** native is ground truth, OCSF is
  the candidate. Running the round natively vs through OCSF on the *same labeled corpus*
  (OTRF) must give the **same verdicts** where the mapping is lossless; every divergence
  must be **explained by a tracked lossy mapping**, never silent. The off-switch is what
  makes this testable — you always have native as the oracle.

## Architecture

```
source events ──(source→OCSF adapter)──> OCSF events ─┐
                                                       ├─> engine (IR / eval_ir / Rust)
Sigma rules ───(pySigma OCSF pipeline)──> OCSF-rules ─┘
       │                                                  native bypass:
       └──────────── native rules ─────────────────────> source events ⋈ native rules
```

- **`source→OCSF` adapter** (workspace-side, one per source): ps → Process Activity
  (`actor.process.cmd_line`, `actor.process.file.path`, parent process…), Sysmon → same
  class, etc. Exact attribute paths verified against the OCSF schema at build time, not
  guessed here. Carries the per-field grade.
- **Sigma→OCSF rule pipeline** (engine-side, reusable): pySigma has OCSF pipeline support;
  rewrites Sigma field references to OCSF attribute paths once, so the *same* rule runs
  against any normalized source. Carries the per-field grade.
- **Vocabulary descriptor** (the seam): a small record naming the vocab of an event stream
  and of a rule set, so the round can assert the pair is coherent before firing and refuse
  (loudly) to fire OCSF rules on native events.
- **Where things live:** the engine and the Sigma→OCSF pipeline are *universal* (canon);
  the source adapters, the vocab choice, and the pins are *workspace* config
  ([[engine_workspace_boundary]]). The manifest records `{vocabulary, source_adapters,
  pipeline_pin, per-detection overrides}`.

## First slice (concrete, scoped)

1. **Vocabulary descriptor + coherence check** in the round: tag events and rules with a
   vocab; `evaluate_round` refuses an incoherent pair. `native` is the default — zero
   behavior change for the existing OTRF path.
2. **Two source→OCSF adapters**: `ps` (already hand-mapped; formalize + grade it) and
   Sysmon (OTRF). Process Activity class only, to start.
3. **Sigma→OCSF pipeline** wired so the T1003.001 rule set can fire against OCSF-normalized
   OTRF events.
4. **Faithfulness gate**: `attest_ocsf_agreement` — native round vs OCSF round on OTRF
   T1003.001 give identical verdicts on lossless-mapped rules; divergences enumerated with
   their lossy-field cause. This is the acceptance test for the slice.
5. **Off-switch demonstrated**: the OTRF round runs `native` (no OCSF) and the macOS `ps`
   round runs `ocsf` (the formalized adapter) — both from the same engine, vocab chosen per
   run.

## Non-goals / deferred

- Concept key / rule dedup (separate thread: content-aware IR signature → catch-set).
- Full OCSF class coverage (network/file/registry/API activity) — Process Activity first.
- Other normalized schemas (ECS, etc.) — the vocabulary-pair seam generalizes to them, but
  OCSF is the only target in this slice.
- Auto-inferring the source→OCSF map (hand-authored + graded first; learned mapping later).
