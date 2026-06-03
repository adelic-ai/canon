# Regime ledger — the applicability map (Level-1 of canon-improves-itself-with-ML)

**Status:** seeded 2026-06-03 (6 rows). Append-only. The machine-readable sibling of
`guarantees_ledger.md`: where the guarantees ledger records *what is proven/validated*, this records
*which primitive wins under which condition*.

## What this is

Each row in `regime_ledger.jsonl` is a `(context → winning primitive)` observation — under what
conditions a detection primitive beats the cheapest alternative. Schema: `contracts/regime_record.schema.json`
(a contract, language-independent). Every row cites the test/experiment that is its source of truth.

It operationalizes the principle this project converged on:

> **Every primitive earns its place by beating the cheapest alternative on an *identifiable condition* —
> and you check the task meets that condition before deploying it.**

A global "which feature is best" ranking *destroys* the information that matters, because **there is no
global regime** — the winner changes with the signal's structure (cardinality / shape / joint / temporal),
the population size, the heterogeneity, and the label quality. The regime ledger keeps that conditioning.

## Why a ledger before a model (the phasing)

We have ~6 rows. Enough to define the schema; nowhere near enough to *learn* a map. So, deliberately:

- **Phase 1 — this ledger.** Cheap, compounding: every future experiment leaves a structured row, so the
  manual regime-mapping we've done for weeks becomes a cumulative dataset instead of isolated results.
- **Phase 2 — Belnap-acquisition experiment.** Use the carrier's structured state as an active-learning
  router (`BOTH` = conflicting evidence → *get a label*; `NONE` = absent evidence → *improve coverage*;
  `TRUE` → deploy; `FALSE` → ignore), and **test it against the standard baselines** (margin / max-entropy /
  random sampling) — does it reach target accuracy with fewer labels? The uniquely-canon piece, held to the
  same "beat the marginals" standard as everything else.
- **Phase 3 — learned applicability model.** Once there are enough regimes: learn `context-meta-features →
  winning primitive`. This is the *algorithm-selection / meta-learning* problem applied to canon's
  primitives, and concretely it is **learning the policy for the tiered, escalating dispatch the
  self-validation architecture already specifies** (it has the dispatch hook; this learns the policy).
- **Phase 4 — self-play regime generation.** A generator learns to evade the detectors (the
  covert-channel / square-root-law duality); the by-product is the varied labelled regimes Phase 3 needs.

`#1` (feature importance) is the **degenerate single-regime case** of Phase 3 — not built standalone.

## How to add a row

After any experiment that pits a primitive against a cheaper alternative, append one JSONL line conforming
to the schema. Record the *condition* that made the winner win in `notes`, and the honest `evidence_tier`
(`validated` real-labels · `constructive` synthetic-mechanism · `fair_test` self-contained · `hypothesized`
expected-untested · `falsified`). `packages/detection/tests/test_regime_ledger.py` validates every row.

## The seed (this session)

<<<
regime (signal_type / population / labels)     winner                  beat
cardinality / large / clean (kerberos-spray)    distinct_count          entropy, conformal
cardinality / small-burst / clean (bots-ct)     distinct_count          conformal (underpowered)
cardinality / large / weak (flaws-ct)           tie (count~entropy)     — (cardinality insufficient)
shape / large / synthetic (dga)                 bigram_cross_entropy    count, char-entropy, length
joint / medium / synthetic (coordination)       mutual_information      marginals (blind)
heterogeneous / large / none (hypothesized)     conformal (HYPOTHESIZED) fixed-k
>>>

The shape of the map is already legible: **count owns cardinality; relational IT (KL/cross-entropy) owns
shape; MI owns joint; conformal's only expected win is heterogeneous per-stratum thresholding — still
untested.** That last row is the next fair test.
