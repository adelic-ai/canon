# Guarantees ledger — what is proven, assumed, validated, capped, deferred, falsified

**Status:** living ledger, 2026-06-02. The epistemic register of the canon spine — the distinction
canon exists to keep: *frameworks are validatable hypotheses; bedrock is logic + empirical reality.*

> **The tests and code are the source of truth.** This ledger records the *epistemic status* of each
> claim — which no single test carries — and points at where it is established. If a claim here ever
> disagrees with the test it cites, the test wins and this file is wrong. A guarantee not backed by a
> cited test is not a guarantee.

Status tags: **PROVEN** (algebraically checkable or empirically property-tested) · **ASSUMED**
(holds only if a named precondition holds; demotes otherwise) · **VALIDATED** (checked on real
labeled data) · **CAPPED** (an honest recorded absence — the floor earned because a stronger claim is
not backed) · **DEFERRED** (named, not built) · **FALSIFIED** (tested and found false; recorded so it
is not re-attempted).

## PROVEN — checkable, and checked

<<<
claim                                                              where (source of truth)
≤_k-monotonicity of every fold (the fold acceptance test),         provenance/monotone.py ·
  exhaustive over the 4-value domain                               test_monotone.py
Belnap bilattice algebra: two orders, truth tables, lfp            provenance/carrier.py · test_carrier.py
Conformal FAR ≤ α, distribution-free, finite-sample, MARGINAL      forge_core/conformal.py ·
  (verified across normal/exponential/uniform/heavy-tail)          test_conformal.py::test_false_alarm_rate_is_controlled_distribution_free
FDR (Benjamini–Hochberg) bounds the false-discovery proportion ≤ q forge_core/fdr.py ·
  (empirical) + BH textbook step-up correctness                    test_fdr.py
IT feature port fidelity: H=−Σp·log2p, D_KL=Σp·log2(p/q),          forge_core/information.py ·
  I(X;Y)=H(X)+H(Y)−H(X,Y) — vs textbook values                    test_information.py
MI plug-in upward bias is cancelled by a permutation null          forge_core/information.py (mi_shuffle_null) ·
  (exchangeable by construction)                                   test_information.py
Derived-field reproducibility guardrail: every derived verdict     forge_core/verdict.py ·
  field recomputes from the emitted primitives (CI-checked)        test_verdict.py::test_trustworthiness_is_reproducible_from_emitted_primitives
One-hash-three-roles keystone: source.id == evidence_digest ==     provenance/entity.py, custody.py ·
  in-toto product digest == root prov:Entity id                    test_custody.py
>>>

## ASSUMED — the tier stands only if a precondition holds (else it demotes)

- **Conformal `bounded`** is conditional on **exchangeability** (calibration ~ test for the normal
  points). Per-input confirmation is unbuilt, so the default monitor is a recorded absence that
  demotes to `well_formed`; pass `exchangeability=TRUE` only when confirmed. `conformal_guarantee_posture`.
- **CFAR `bounded`** is conditional on the **homogeneous-reference-window / noise model**. The detector
  node claims `bounded`; the per-result monitor selects whether it stands. (And: CA-CFAR's square-law α
  is mismatched to a *bounded* statistic like entropy — see FALSIFIED-adjacent note below.)
- The `bounded` and `machine_checked` tiers are **assumption-bearing** by construction: a non-confirming
  runtime monitor caps them at the floor and records the demotion. `provenance/guarantee.py`.

## VALIDATED — on real labeled telemetry (`faker-kerberos`)

Detailed record + the exact assertions: `packages/detection/README.md` (the validation source of truth).

- **Fan-out family** (hard anomaly, exact validation): password-spray (T1110.003) — all 3 labeled
  source IPs, 0 FP; service-ticket fan-out (T1558.003) — all 4 Kerberoast accounts + 2 pass-the-ticket,
  0 FP. `test_fanout.py`.
- **Off-hours family** (soft anomaly): **recall** (both labeled off-hours) + **specificity** (0 service
  accounts). **Precision deliberately not claimed** — unlabeled natural night activity is *unidentifiable,
  not false*. Representing graded evidence honestly is the point. `test_offhours.py`.

## CAPPED — honest recorded absence (the floor, because more is not backed)

- **`machine_checked` is never claimed without a proof artifact.** The ingest decode's *ceiling* is
  machine_checked (a bit-faithful reinterpret is an algebraic identity), but with no proof its monitor
  is a recorded absence demoting to `well_formed` — **liftable by design** (`proof=TRUE` once an F\*/Coq
  proof exists). `forge_core/ingest.py` (decode_guarantee_posture), `test_ingest.py`.
- **Features/decodes cap a detection at `well_formed`.** Any unverified computation on the
  guarantee-critical chain (the decode; the entropy/KL/MI feature) caps the end-to-end tier at the
  floor by weakest-link — a property of having any unverified step, and a feature is one.
- **`custody = NONE` on unattested telemetry.** A CSV is not signed evidence, so verdicts report
  custody/trustworthiness `NONE` while the detection stands — no faked attestation. `detection/_verdict.py`.
- **Source tier-transparency:** a raw source carries no rigor tier (its trust is the orthogonal custody
  axis), so it never drags a result to the floor; absence-of-claim is `None`-like, not `False`-like.

## DEFERRED — named, not built

- **F\*/Coq machine-checked proofs** (the polyglot path) — the only thing that lifts a decode/kernel to
  `machine_checked`. §4 of the architecture.
- **SHACL shapes** — `contracts/shapes/` is still README-only; the well-formedness fold is built but not
  domain-enforced.
- **Multi-scale** — the divisibility lattice (`forge_core/lattice.py`) is built but unused by the
  detectors; the grain-divisibility discipline beyond a single window, with the materialized-bucket
  guard, is future work. Earns its keep first at multi-scale MI (coordination cadence).
- **MI-coordination** — built primitive (`windowed_mi` + permutation null), but **no validatable corpus**:
  `faker-kerberos` has no sustained coordination (FALSIFIED below). Needs BOTS v3 Windows (lateral
  movement, CTF ground truth) or an explicitly-labeled injected signal.
- **General `Binding`** — `FanoutBinding`/`TemporalBinding` are too different to parent yet; wait for a
  third detector family. Shared *behavior* (verdict emission) is already extracted; shared *ontology* is not.
- **`cost` fold** — the one §3 fold unbuilt.

## FALSIFIED — tested and found false (recorded so it is not re-attempted)

- **The lattice as a structure *discoverer*** (e-forge lab/001–003, prior work). `Var(Δ_p F)` is
  PSD-determined; cross-prime correlation is a signal-independent filter-geometry constant; `discover_scales`
  is divisor-enumeration-with-IT-scoring, not IT-driven scale selection. The divisibility lattice is sound
  as **windowing plumbing**, falsified as a **detector**. See the `discover_scales-critique` memory.
- **H of Div(H) as load-bearing** — deflated 2026-06-01: the **GLB/grain** (meet, the bottom) does the
  nesting/aggregation work; the **LCM horizon** (join, the top, phantom) earns nothing you need. Keep the
  grain-divisibility discipline; drop the real-analysis horizon construction. (Aggregation free-lunch is
  additive-only — counts/energy, **not** the intensive IT features.)
- **FDR over a full T0 cell sweep** detects nothing — the discrete conformal floor `1/(n+1)` is ~`1/q`
  times the BH threshold `q/m` at ~10⁴ cells. Not a failure of FDR: it is a **T1/discovery** control
  (reduced multiplicity, clean null), and a T0 sweep uses a per-cell α. `test_fanout.py`.
