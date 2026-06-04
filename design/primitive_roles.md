# Primitive roles — the thin semantic input the substrate consumes

**Status:** seeded 2026-06-04. The load-bearing slice of the primitive-semantics that the self-validation
substrate actually needs — NOT the full Atlas. A primitive can fail in one role and earn its keep in
another; this table records *which role each canon primitive serves*, so the verdict path can wire the
"disqualified" detectors in as **checks** and **calibrators**.

> **The reframe:** the detection experiments answered "is X a good detector"; the honest answer was "good
> *for what*." Conformal lost as a detector because it was never one — it's a *calibrator*. Entropy ≈
> distinct-count is a *redundancy*, which is exactly a *cross-check*. The detection battery was generating
> empirical **role evidence**, and the regime ledger's `winner`/`beaten` is that evidence. This table is the
> thin canon-specific slice; the broad reference is Atlas (`~/atlas`), linked later by primitive identity.

## Roles

Vocabulary (aligned with Atlas `ap:role`): **detector · check · calibrator · feature · summary.**
A primitive has MANY; "weak as a detector" ≠ "no value."

<<<
primitive (canon op)              detector            check                 calibrator    other
distinct_count (fanout)           ✓ (cardinality)     ✓ (vs entropy)                      feature
shannon_entropy                   weak (relational    ✓ (vs distinct_cnt)               feature, summary;
  / windowed_entropy                forms win only)                                       malware/crypto (other domains)
kl_divergence / windowed_kl       ✓ (shape: DGA)      ✓ (drift-from-baseline)            feature
cross-entropy (n-gram)            ✓ (shape: DGA)                                          feature
mutual_information / windowed_mi  ✓ (joint/coord)     ✓ (redundancy between primitives)  feature; side-channel
conformal (pvalues/far_bound)     —                                         ✓ (FAR)       check
fdr_control                       —                                         ✓ (multiplicity over a batch)
ca_cfar / os_cfar                 ✓ (adaptive thresh)                       ✓ (sets thresh at constant FAR)
cusum                             ✓ (drift/changepoint)
matched_filter                    ✓ (known template)                                     feature
energy_detector                   ✓ (unknown signal)
goertzel                          ✓ (known freq)                                          feature
welch / band_power                                                                        feature (spectral)
lock_in                           ✓ (coherent tone)                                       feature (envelope)
butter / notch / band_power_bank                                                          feature (preprocess)
circular (resultant/mean)         ✓ (off-hours)                                           feature
ingest (validate/decode)                              ✓ (validity / well-formedness)
>>>

## Check-pairs — the wiring target (redundant measures that should AGREE → `BOTH` on disagreement)

The self-validation thesis needs independent measurements that cross-check; the detection-redundant
primitives are exactly those validators. The disagreement is a Belnap `BOTH` (a soundness alarm), not noise.

1. **`distinct_count` ⟷ `entropy`** — two measures of fan-out spread. Normally agree (the whole reason
   entropy was "redundant" at detection). On disagreement → `BOTH`: either a measurement fault, a parser
   evasion, or an attacker gaming one statistic but not the correlated one (evasion-robustness — gaming both
   jointly is harder than gaming one). **The first cross-check to wire.**
2. **conformal-FAR ⟷ CFAR-analytic-FAR** — two false-alarm-rate estimates that should agree where both
   apply (the analytic-vs-conformal pairing already noted in the guarantees ledger). Disagreement caps the
   tier / raises `BOTH`.
3. **∃-detect ⟷ ∀-validate** — the existing detect/validate duality; `BOTH` already wired in the verdict.

## Calibrators (FAR / threshold / multiplicity — honesty, not detection)

- **conformal** → distribution-free FAR bound on any detector's score (its canonical role; never a detector).
- **CA/OS-CFAR** → adaptive threshold at a constant analytic FAR.
- **fdr_control** → multiplicity correction over a batch of decisions.

## How the substrate consumes this

The verdict path (`forge_core.verdict` / `detection._verdict`) currently folds a single detector. The next
substrate step: for a detection that has a **check-pair**, compute both, and set the cross-check carrier =
`BOTH` when they disagree (carried in the verdict alongside the primary decision); attach the **calibrator**
(conformal/CFAR FAR) to every verdict's guarantee. That turns "no result asserted without justification"
from a slogan into an independently cross-checked, calibrated verdict — using the primitives that *lost at
detection* in the roles where they win.

## Links (future, lightweight — do not build wholesale up front)

- Each row → its Atlas IRI (`ap:entropy`, `ap:conformal-prediction`, …) — the identity bridge.
- The regime ledger's `winner`/`beaten` → the same IRIs — so "what won (evidence)" and "what it is
  (reference)" reference one identity. Atlas = reference; regime ledger = evidence; this table = the
  canon-op role slice the substrate needs *now*.
