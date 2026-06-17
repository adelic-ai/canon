# Guarantees ledger — what is proven, assumed, validated, capped, deferred, falsified

**Status:** living ledger, 2026-06-02. The epistemic register of the canon spine — the distinction
canon exists to keep: *frameworks are validatable hypotheses; bedrock is logic + empirical reality.*

> **The tests and code are the source of truth.** This ledger records the *epistemic status* of each
> claim — which no single test carries — and points at where it is established. If a claim here ever
> disagrees with the test it cites, the test wins and this file is wrong. A guarantee not backed by a
> cited test is not a guarantee.

> **Machine-readable sibling: `regime_ledger.jsonl`** (schema `contracts/regime_record.schema.json`). Where
> this file records *what is proven*, the regime ledger records *which primitive wins under which condition*
> — the applicability map, and the seed dataset for a future learned dispatch policy. See `regime_ledger.md`.

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
Detection guarantee tier is SHACL-EARNED, not asserted:            detection/_verdict.py ·
  well_formed iff validate(root).conforms in emit (else ABSENT);   test_guarantee_earned.py
  tier follows the validator — drops on non-conformance.
  [FIXED 2026-06-14: emit had hardcoded tier=WELL_FORMED, no
  validate() in the path — asserted, not earned.]
>>>

## ASSUMED — the tier stands only if a precondition holds (else it demotes)

- **Conformal `bounded`** is conditional on **exchangeability** (calibration ~ test for the normal
  points) — and the monitor is now BUILT (2026-06-17): `exchangeability_monitor` (forge_core/conformal.py)
  is a **falsification** check — split-half two-sample KS over the calibration scores in time order →
  `TRUE` (no drift detected; the most an empirical check earns), `FALSE` (calibration non-stationary →
  violated), `NONE` (too few → recorded absence). It gates the tier via `conformal_guarantee_posture`:
  `emit_detection_verdict(exchangeability=…)` claims `BOUNDED` on the conformal `detection` node (over a
  SHACL-well-formed graph, so the demotion floor is earned), and the guarantee fold stands it on `TRUE` /
  demotes on `NONE`/`FALSE`. Wired into the fan-out (`fanout_verdicts` computes it once per run). **Earned
  end-to-end:** faker-kerberos (stationary) → `bounded`; flaws CloudTrail (drifting calibration) → demoted
  to `well_formed` — the substrate refusing the bound it can't back. `test_conformal.py`, `test_bounded.py`.
  **Scope (honest):** confirms calibration *stationarity* (one necessary condition / the "stale calibration"
  threat), NOT full exchangeability — test-time distribution shift + calibration-contamination are
  complementary monitors, deferred. `TRUE` = "no evidence against the precondition," exactly the
  assumption-bearing footing `bounded` is defined to carry.
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
- **Fan-out, third binding — a new domain, SIGNAL validated, detection capped** (BOTS v3 CloudTrail,
  2026-06-03): the *same* fan-out detector over AWS CloudTrail, changing only the loader. The cryptojacking
  credential `web_admin` (ATT&CK **T1496** Resource Hijacking on a **T1078.004** cloud credential) swept
  `RunInstances` across **all 15 AWS regions** → near-maximal region entropy (≈ log2(15) = 3.9 bits),
  cleanly separated from every other identity (≤ 1.2 bits). **Signal validated, exact ground truth.**
  Detector reuse validated: only `load_cloudtrail_events` is new. `test_cloudtrail.py`. **But the standing
  conformal sweep does NOT fire — see CAPPED.**
- **Sigma corroboration panel — independent external confirmation, deduped, on real rules (2026-06-16).**
  A SECOND, external witness (`detection/sigma_panel.py`): FCA-deduped community rules (logsource +
  field-set = one concept = one vote) corroborate a canon finding, so the verdict is more than canon's own
  word and is not inflated by counting near-duplicate rules. **Belnap ONE-SIDED by construction** — `TRUE`
  (≥1 deduped class fires) or `NONE` (silent); never `FALSE`, because a community rule *not* firing is a
  coverage gap, not evidence of absence. Recorded as a **PROVENANCE EDGE** on the verdict root (a
  `sigma_corroboration` derivation `prov:used` one entity per fired rule-class), **not** overloaded onto
  `cross_check` (which stays a within-evidence redundant-measure check; the two are different epistemic
  axes). Validated on the real SigmaHQ corpus (3748 rules) + OTRF/flaws: T1003.001 (comsvcs CallTrace) and
  T1580 (`aws_enum_buckets` on a native `ListBuckets`) corroborate. The per-detector **coverage map**
  (`design/sigma_corroboration_coverage.md`) records the honest spectrum — **2/7 corroborated, 5 named
  gaps** (`no-overlap` / `no-same-logsource`), negatives as data not silence. `test_sigma_panel.py`,
  `test_sigma_panel_general.py`, `test_cross_check_sigma.py`, `test_coverage.py`.

## CAPPED — honest recorded absence (the floor, because more is not backed)

- **`machine_checked` is never claimed without a proof artifact.** The ingest decode's *ceiling* is
  machine_checked (a bit-faithful reinterpret is an algebraic identity), but with no proof its monitor
  is a recorded absence demoting to `well_formed` — **liftable by design** (`proof=TRUE` once an F\*/Coq
  proof exists). `forge_core/ingest.py` (decode_guarantee_posture), `test_ingest.py`.
- **Features/decodes cap a detection at `well_formed`.** Any unverified computation on the
  guarantee-critical chain (the decode; the entropy/KL/MI feature) caps the end-to-end tier at the
  floor by weakest-link — a property of having any unverified step, and a feature is one.
- **`custody = NONE` on unattested telemetry — but now EARNABLE (2026-06-17).** A CSV is not signed
  evidence, so by default verdicts report custody/trustworthiness `NONE` while the detection stands — no
  faked attestation (the honest floor, still the default). Custody is now earnable end-to-end:
  `emit_detection_verdict(evidence=<bytes>, attestation=<CustodyAttestation>)` anchors the source on its
  content digest (the keystone — source CID = digest = the vouched `product_digest`) and the custody fold
  returns `TRUE` (signed + digest-match), `FALSE` (mismatch = tamper), or `NONE` (unsigned / silent feed).
  Constructive existence-proof — the bytes + attestation are synthesized (no signed feed in the corpora;
  real DSSE verification is the deployment boundary, `detection/ingest.py::attest`); `test_custody.py`.
  **Precondition-gated (2026-06-17):** `track_custody=False` (no attested feed in this deployment — the
  common case, since virtually nothing signs logs) PARKS the axis: custody + trustworthiness are *omitted*
  from the contract (schema relaxed to optional), a **precondition-absent** state distinct from an
  evaluated `NONE`; the renderer shows `parked`. The decision is never touched. Matches the discipline by
  which off-hours is already registry-gated (it isn't run when `_time`/`Account_Name` are absent) — an axis
  whose precondition can't hold in a deployment is parked, not surfaced as a misleading per-verdict `NONE`.
  **Composition with corroboration — RESOLVED (2026-06-17).** A corroboration's Sigma rule-sources are
  knowledge applied TO the evidence, not evidence, so they are marked `reference=True` and the evidence-
  custody fold EXCLUDES them (a reference input is custody-N/A — not folded as `NONE`, not faked `TRUE`).
  An attested + corroborated verdict now earns custody `TRUE` (the rules don't drag it) while the
  corroboration edge stays in provenance; unsigned + corroborated is still `NONE` because the *evidence*
  is unattested, not the rules. Reference-data integrity (is the rule itself tampered?) is a separate
  concern (analytic provenance), deliberately NOT evidence-custody. `provenance/entity.py` (`reference`
  flag + `is_reference`), `custody.py` (fold skips reference inputs); `test_custody.py` (both layers).
- **Source tier-transparency:** a raw source carries no rigor tier (its trust is the orthogonal custody
  axis), so it never drags a result to the floor; absence-of-claim is `None`-like, not `False`-like.
- **Conformal is empty without a population — capped to silence on a burst, and the detector emits no
  verdict** (BOTS v3 CloudTrail, 2026-06-03). The whole attack is a ~38-min window → ~11 `(credential,
  hour)` cells, so the conformal floor `1/(n+1) ≈ 0.08` sits *three orders* above the `alpha=1e-3` that
  works on 30-day Kerberos. The standing sweep flags nothing; `web_admin` (the visual attacker) gets
  p ≈ 0.17. Correctly, the detector then **asserts nothing** — no verdict manufactured for a detection the
  calibration can't justify (the north star, applied to our own output). Same structural fact as the
  FDR-over-cells finding. `test_cloudtrail.py`.
- **Conformal's detection marginal value is UNPROVEN on real data — measured both ways, 2026-06-03.** The
  long-open question, now resolved on both available real corpora, and the answer deflates the conformal
  narrative (recorded, not avoided — this is what the ledger is for):
    - **burst (BOTS CloudTrail):** the trivial `distinct-region-count > 5` baseline isolates `web_admin`
      *exactly* (0 FP) where conformal stayed silent — **baseline beats conformal** (conformal needs a
      population the burst can't supply). `test_cloudtrail.py`.
    - **large population (faker-kerberos, 30-day, where conformal *works*):** held against the *best
      justifiable* baselines (not a strawman), conformal-entropy has **no detection advantage over
      `distinct-count > k`** — spray IPs touch 20 distinct accounts, *no* normal IP exceeds 3, so
      `distinct > 5` catches all three sprays 0 FP (identical to conformal) at a *wider* margin (17 vs
      entropy's 2.7). The entropy *feature* and the conformal *calibration* are both unnecessary for
      detection here; the signal is fully in the simplest statistic. (Raw volume does *not* separate —
      it is the fan-out/distinct-count, not activity, that carries it.) `test_baseline_comparison.py`.
  **So: in neither real corpus has conformal's *detection* advantage been demonstrated.** What conformal
  genuinely provides is *orthogonal to detection* — distribution-free **automatic threshold selection** (no
  hand-set `k`) + a **calibrated FAR bound** — i.e. the same detection with the threshold chosen by a
  population instead of a human, and an error bound attached; real, but not better separation. This applies
  the *same* "beat the marginals" standard we held MI to, back onto conformal — and on real data it has not
  cleared it. **To prove conformal's detection value** a corpus is needed where the simple statistic does
  *not* separate but conformal does (heterogeneous entities needing per-entity adaptive thresholds, or where
  distribution *shape* matters and count does not) — a specific, falsifiable target.
  *flaws.cloud — re-probed and FOUND USABLE (correcting a prior note that wrongly called it "unlabeled";
  3rd wrong guess about this dataset, each from reasoning instead of loading the file):* large + real
  (~2M records, 2017–2019) with **derivable identity-based ground truth** — the documented challenge
  identities appear by name: `backup`/`Level6` are the *compromised* creds, abused for a massive
  **RunInstances cryptojacking flood** (~320K events, InstanceLimitExceeded/Unauthorized errors — same
  class as BOTS `web_admin`, at 2.5-yr scale and 100× volume), while `piper`/`flaws`/`SecurityMonkey`/`Root`
  are the legitimate owner/infra baseline. So it furnishes **both real positives and a normal population at
  large scale** — the very large-real-population instrument the conformal-vs-baseline question wanted.
  Caveat: labels are *identity-derived* (not per-event), and the leaked creds were also used by legit
  challenge players, so most `backup`/`Level6` activity is NOT the cryptojacking (weak labels). **The
  comparison was then RUN (`packages/detection/experiments/flaws_conformal_vs_baseline.py`) and the lead
  did NOT survive** — confirming the Kerberos finding on a second, larger, real corpus:
    - A first-pass *per-identity max* view suggested entropy (3.97) separates where distinct-count fails
      (legit `flaws` infra touches 17 regions). **That was a max-aggregation artifact.** At the proper
      **cell level** (Mann-Whitney AUC of POS vs LEGIT cells), region-entropy ≈ distinct-count at *every*
      grain — DAY 0.761 vs 0.759, HOUR 0.601 vs 0.587, 15-min 0.542 vs 0.530 (within ~0.02). Finer grain
      made it *worse*, not better. **Entropy earns no feature advantage over the trivial count (Q1: no).**
    - Conformal on that weak feature gives recall ≈ FAR (0.10 vs 0.08 at α=0.05, day) and FAR *exceeds*
      nominal α (noisy real labels violate exchangeability) — calibration cannot rescue a non-separating
      feature. **Conformal adds no detection over a fixed threshold (Q2: no).**
  **So conformal/entropy's detection advantage is now unproven on TWO real corpora** (Kerberos: baseline
  ties; flaws: entropy ≈ count, neither separates the noisy-labeled compromise via region fan-out). The
  discriminating corpus — where the richer feature robustly beats the count — has NOT been found; the
  search for it (or the standing conclusion that the sophistication is unearned on real data) continues.
- **IT-feature value LOCATED — it's *which* IT feature, not IT-vs-baseline (the first positive IT result).**
  DGA char-entropy fair test (`packages/detection/experiments/dga_entropy_fair_test.py`): real English words
  vs documented DGA algorithms, char-entropy held against the best cheap baselines by AUC. Result (|disc| =
  |AUC−0.5|, random DGA): **naive char-frequency Shannon entropy is WEAK (0.200), beaten even by trivial
  vowel-ratio (0.409)** — third strike for symbol-entropy (redundant on fan-out, mediocre here). **But the
  IT approach done RIGHT wins decisively: KL-from-English (0.423 — canon's `kl_divergence`) and bigram
  cross-entropy (0.499, near-perfect).** Same split MI surfaced: the **marginal/symbol-frequency** IT
  feature (Shannon entropy) is weak; the **relational/conditional/reference-based** IT features
  (KL-from-reference, cross-entropy, MI) carry the signal. **Product guidance (feature engineering is a
  product): ship KL / cross-entropy / MI; demote naive Shannon entropy to a cheap-but-weak add-on.**
  Caveats: benign = dict-words proxy (no real top-domains list, no net); simplified DGA generators; the
  dict-DGA `length` separation is a generation artifact; single-feature AUC, not a fitted model — *fair-test
  demonstrated, not validated on real DGA feeds.* Also reframes the prior conformal/entropy negatives: those
  used naive symbol-entropy on cardinality tasks (count's home turf) — doubly off-turf for an IT feature.
- **"Constructively validated capability" — a named tier between PROVEN and VALIDATED, and a recorded
  ceiling.** The MI coordination family (`detection/coordination.py`) is shown to work on a *synthetic
  mechanism-modelled* corpus (recovers the coordinated set, beats the marginals), which is **more than
  PROVEN** (it's an end-to-end detector on data, not an algebraic identity) but **less than VALIDATED**
  (the data is synthetic, ground truth ours by construction). The capability is backed; the operational
  value is an **honest recorded absence** — not claimed, because synthetic existence ≠ field evidence. The
  discipline that keeps the tier honest: the corpus models an *attack mechanism* and lets the MI signal
  *emerge* (as faker-kerberos's fan-out emerged from the spray), rather than planting an MI-shaped target —
  otherwise "MI beats the marginals" would be teaching-to-the-test. `test_coordination.py`.
  **Earns this tier iff ALL FOUR hold (else it is just a mechanics/`well_formed` test, not this tier — the
  tier must stay rare or it rots into a second VALIDATED):** (1) it **beats a cheaper/marginal alternative**
  on the same corpus (distinct capability, not merely "the detector fired"); (2) the corpus is
  **mechanism-modelled** — the signal *emerges* from a modelled mechanism, never planted to fit the detector;
  (3) a **negative control** passes (remove the mechanism → the detector goes quiet); (4) it **explicitly
  declines** operational value (synthetic ground truth). Miss any one and it does not earn the tier. The
  scope of the claim is exactly "*there exists at least one **mechanism-modelled** scenario where this method
  has value beyond the marginals*" — **not** "...at least one *realistic/operational* scenario" (that is the
  deferred question; do not let the word "realistic" smuggle the synthetic result toward a field claim).

## DEFERRED — named, not built

- **Entity/incident-grain cross-model corroboration — CONSTRUCTIVE existence-proof BUILT (2026-06-16);
  real-data validation deferred.** A behavioral detector and an external rule that read *different events*
  corroborate only at the **entity + window grain** (the same actor's full multi-EID stream in the flagged
  window), not by scoring one's single event against the other's rule (different telemetry → no fire).
  Built in `detection/cross_model.py` + `test_cross_model.py`: the 4769 RC4 ticket fan-out (T1558.003)
  flags an account, then the deduped windows/security Sigma panel runs over that account's full window
  stream; firing rule-classes land as the provenance edge. On a **mechanism-modelled** corpus with a
  **negative control**: the Rubeus actor (4769 fan-out + the EID-4611 `User32LogonProcesss` artifact) is
  corroborated by **two** witnesses — `win_security_kerberoasting_activity` (behavioral, 4769 RC4) *and*
  `..._register_new_logon_process_by_rubeus` (tool); the **non-Rubeus actor (Impacket)** flags identically
  and is corroborated by the **behavioral rule only**, the Rubeus artifact honestly **absent (NONE, never
  FALSE)** — Kerberoasting is a *technique, not a tool*, so Rubeus is ONE witness, not the definition. A
  normal account also trips the per-event community rule but is **not behaviorally flagged** (the fan-out
  adds the discrimination the per-event rule lacks). Belnap/CID check: the rubeus verdict's provenance CID
  equals the root rebuilt WITH the corroboration and differs from the one without — the edge is genuinely
  on the verdict. **Deferred:** real-data validation — no held corpus carries both traces (OTRF is
  process_access only; faker-kerberos is 4769-only; bots-v3 has no kerberoasting). Two traces: the 4769 RC4
  fan-out is technique-intrinsic (every tool leaves it); the 4611 artifact is Rubeus-incidental (only on
  ops needing `SeTcbPrivilege`). Complementary, not ranked — "lower on the pyramid of pain" = cheaper to
  **evade**, not lower **value** (commodity Rubeus is widespread → the tool rule is high value-now; the
  behavioral signal is evasion-resistant). `design/sigma_corroboration_coverage.md`.
- **F\*/Coq machine-checked proofs** (the polyglot path) — the only thing that lifts a decode/kernel to
  `machine_checked`. §4 of the architecture. **Cost-deferred, NOT value-deferred** — its purpose is
  *adversarial numeric robustness*: the only tier that holds against an input an attacker *chose* (not one
  nature drew), because the numeric parts of `well_formed`/`bounded` are SAMPLED (property tests) and a
  proof is over ALL inputs. Defends against minute, **in-tolerance** manipulation of the computation
  (threshold-boundary evasion via the round-off window; CUSUM/Welch accumulation drift; float
  non-associativity via input reordering). Load-bearing beyond cyber detection — high-assurance
  engineering and **ICS/OT/SCADA** (Stuxnet = in-tolerance manipulation + falsified telemetry; the rigor
  DO-178C / IEC 61508 already mandate). Socket already cut (`decode_guarantee_posture(proof=TRUE)` lifts
  it). See architecture §4 "Why the top rung matters."
- **SHACL shapes** — the GENERIC well-formedness check is now ENFORCED in the detection emit path
  (2026-06-14): `emit_detection_verdict` runs `validate(root)` (provenance `well_formed_shapes`) and the
  guarantee tier follows `.conforms` — see PROVEN. Domain shapes are now WIRED into the emit tier-earning
  (`_well_formed_shapes` merges generic + every `contracts/shapes/*.shapes.ttl`):
  (1) `detection.shapes.ttl` (2026-06-16) — every op-plan must record `canon:params` (the re-derivable
      recipe); core SHACL; `test_domain_shapes.py`.
  (2) `cross_model.shapes.ttl` (2026-06-17) — a `sigma_corroboration` must be BACKED BY ≥1 sigma-rule
      witness it actually `prov:used`: **corroboration earned, not asserted** — the verdict's own provenance
      must exhibit the witnesses or the tier drops to ABSENT. CORE SHACL via OWL+SHACL dual-typing (below);
      ships PASS/XFAIL; `test_cross_model_shapes.py` (incl. a tamper test: drop the witness edges → fails).
  Both ship the PASS/XFAIL generator-validator pairing.
  **OWL+SHACL dual-typing — DONE (2026-06-17).** `to_prov` now types every activity by its op
  (`a <urn:canon:op#{op_name}>`), so domain shapes `sh:targetClass` the op directly instead of selecting it
  by `canon:opName` via a SPARQL target. This let `cross_model.shapes.ttl` be written in pure core SHACL
  (`sh:targetClass` + `sh:qualifiedValueShape`), so the transient `advanced=True` (added then reverted) is
  no longer needed. Still pending: more per-op/per-technique shapes; full OWL class declarations
  (`owl:Class` + `rdfs:subClassOf`) for reasoning, if a consumer pulls it.
- **Multi-scale** — the divisibility lattice (`forge_core/lattice.py`) is built but unused by the
  detectors; the grain-divisibility discipline beyond a single window, with the materialized-bucket
  guard, is future work. Earns its keep first at multi-scale MI (coordination cadence).
- **MI-coordination** — primitive built, and a **constructive existence-proof now built too**
  (`detection/coordination.py` + `test_coordination.py`, 2026-06-03): on a synthetic corpus *modelling a
  mechanism* (synchronized multi-host C2 beaconing — a shared beacon schedule, **not** a planted MI-shaped
  blob), MI + FDR recovers **exactly** the coordinated host pairs (full recall, 0 false pairs) **and beats
  the marginals** — each coordinated host is individually indistinguishable from normal (activity rate /
  entropy ranges overlap), so no single-stream detector can separate them; only the joint sees it. This is a
  **constructively validated capability** (the precise tier — implementation works + catches a
  mechanism-derived pattern + beats marginals on a controlled example), and it is explicitly **NOT**
  operational validation: the signal is synthetic, ground truth ours by construction. It moves MI off
  fully-`None` for the *capability* question while leaving the *operational* question at `None`.
  **What remains DEFERRED is a real-data corpus** — and the search there turned up an **emerging pattern**
  (probed 2026-06-02→03): three *real* corpora examined, all show *single-entity distribution collapse*,
  none show the *sustained two-stream dependence* MI is for —
    (a) `faker-kerberos`: point/burst spray (FALSIFIED below);
    (b) BOTS v3 Windows-Security **export**: no network-logon lateral movement (291 logons, all logonType 5
        service; zero Type 3/10) — *scope: the SPL-derived JSON export, not the full `botsv3.tgz` index,
        which is unprobed; absence-in-an-export ≠ absence-in-the-corpus*;
    (c) BOTS v3 CloudTrail: real attack but a ~38-min single-credential burst (web_admin → RunInstances),
        again a fan-out/collapse signal, not sustained coordination.
  **Three claims, kept separate (the load-bearing distinction — do not collapse them):**
    - **Claim A — *our currently-held corpora* furnish no validated MI target.** Weaker than first written.
      The three corpora are too small / too particular to have *tested* MI in the first place:
      faker-kerberos's generator plants *point/burst* anomalies, never coordination (the test is not given
      by construction); BOTS CloudTrail is **38 minutes / ~11 identities** (cannot resolve *sustained*
      dependence or establish a normal-independence baseline); BOTS-Windows is a process-noise export. So
      the carrier value of "MI adds value" from this evidence is **`None` (no information — the instrument
      could not see it), not `False` (tested and failed).** Writing this as "well-supported" was the
      **`None`→`False` drift** this very project exists to prevent — the absence-of-evidence/evidence-of-
      absence error, committed in canon's own register. *What is genuinely supported* (`None`-resistant):
      entropy/fan-out anomalies are abundant and these corpora surface them readily; faker-kerberos
      demonstrably produces point/burst, not coordination. The honest statement is **not** "our corpora lack
      an MI target" but "**we have not yet had a corpus capable of running the MI experiment, in either
      direction**" (increase *or* collapse — see the two-models note in DEFERRED actions). Action unchanged;
      its justification changes from "keep looking in case the answer differs" to "the experiment is unrun."
    - **Claim B — *cyber telemetry generally* lacks MI-worthy signal.** **NOT supported, and must not be
      inferred from A** (especially now that A itself is only `None`). The examined search space (three
      corpora) is negligible against what exists:
      public intrusion sets, academic *beaconing* datasets, network-flow corpora, malware-sandbox traces,
      cloud-attack simulations, ATT&CK-emulation telemetry, DARPA-era corpora, honeypot collections,
      red-team exercise logs (often richest — intentional, documented attack narrative), plus thousands of
      proprietary sets. Hardness-to-validate is **not** evidence of unimportance — plausibly the opposite
      (see below).
  **The actual requirement is narrower than "a corpus with `I(X;Y)>0`."** The target must be one where the
  joint dependence *adds value beyond the marginals*: individual streams weak / noisy / ambiguous, yet the
  coupling strong. A 500-host botnet beaconing every 60 s may light MI up beautifully, but if each host is
  *individually* an obvious periodic-beacon hit, MI has proven nothing — the marginal detector already won.
  This is the *same* species of question as the conformal-vs-trivial-baseline gap (now partly answered, see
  VALIDATED/CAPPED): a method earns its keep only where it beats the cheaper alternative. Candidate target
  classes to look for (weak-marginal + strong-coupling): multi-host beaconing (host-A timing × host-B
  timing), distributed credential relay (account stream × host stream), multi-stage campaigns (two entity
  classes that become coupled *during* the attack).
  **Two MI operating models — directions on one statistic (the durable, architecture-level refinement).**
  Recorded as **fact** (survives independent of any dataset claim):
    - **increase / coordination-emergence** — `I(X;Y) ≈ 0` normally, `↑` under attack: streams normally
      independent become dependent (coordinated beaconing, distributed credential use, synchronized actors).
      *This is what canon implements* — `windowed_mi` + `mi_shuffle_null`, flagging MI above an independence
      (shuffle) null. **Built.**
    - **collapse / coupling-breakdown** — `I(X;Y) ≫ 0` normally, `↓` under attack: streams normally coupled
      decouple (sensor spoofing, process injection, physical-system manipulation). Requires a
      *baseline-coupling reference* + a *below-baseline* test (conformal could supply the FAR on the
      deviation). **Not built.** Mirrors entropy collapse-vs-expansion: same statistic, opposite directions
      — naming both *completes the detector family conceptually* even with one implemented.
    Consequence (resolves a recurring tension — "why can't we find MI corpora?"): we were searching only the
    *increase* half; admitting collapse as a first-class anomaly type enlarges the search space.
  Recorded as **hypothesis, not fact** (flagged; probe before adopting, exactly as BOTS was probed): the
  collapse model *may* fit canon better — forge-core is already a coupled-sensor DSP spine
  (Welch/CFAR/Goertzel/matched-filter) — and public ICS corpora with coupled sensors + labeled injection
  attacks (SWaT, WADI, BATADAL, HAI) *appear* to be plausible MI-collapse validation candidates and **should
  be investigated**. "ICS is the better-fit target" and "those datasets are adequate instruments" are leads,
  **not** ledger facts. (External-LLM-sourced framing.)
  **Why this may matter more, not less.** Entropy/fan-out catch *concentration / collapse* — which occur
  constantly, hence the easy validation. MI targets *coordination / coupling / dependence* — inherently more
  structural, and apparently rarer in readily-available data. The difficulty of validation may indicate MI
  is aimed at a rarer and higher-value class of phenomena, not a useless one.
  **Standing observation (the durable statement):** locally-examined *real* corpora readily furnish
  entropy/fan-out anomalies but have *not yet* furnished an *adequate real instrument* for the MI experiment.
  A **synthetic** adequate instrument now exists and the *capability* experiment is **run and passed**
  (constructive proof above: MI recovers the coordinated set and beats the marginals). What is still unrun is
  the **operational** experiment — on real data — and the negative result there remains **instrument-limited
  (`None`), not a finding about MI (`False`)**. **Further (real) corpus exploration required** (ICS
  coupling-collapse is the leading lead); MI's operational value stays DEFERRED. Do not re-attempt the
  *operational* claim on a corpus before confirming *both* a signal (increase or collapse) *and* that it beats
  the marginals — the synthetic proof shows the capability is real, not that any given real corpus exercises it.
- **General `Binding`** — the "wait for a 3rd family" gate is now **met**: `CoordinationBinding` (the
  two-stream shape) joins `FanoutBinding`/`TemporalBinding`, and the shared *behavior* (verdict emission via
  `emit_detection_verdict`) generalized cleanly across all three. But generalization stays **deliberately
  unforced** — extract a general `Binding` only if the three shapes actually *rhyme* (concrete-first), not
  because a counter reached three. Shared *ontology* still not demonstrated; the two-stream shape is in fact
  quite different (pairs, not entity→value), which is mild evidence *against* a clean common parent.
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
