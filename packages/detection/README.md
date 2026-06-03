# detection — telemetry → spine, validated on real data

The orchestration layer above `forge-core`. forge-core is the domain-agnostic statistical spine
(features, tests, FP control); this layer holds **telemetry semantics**: turning real events into
candidate streams, choosing the grain, dispatching forge-core's primitives, and projecting results
into the canonical `DetectionVerdict`.

Three detector **families**, with deliberately different validation regimes:
- **fan-out** (`fanout.py`) — `entity → distribution over values`, a **hard** anomaly (exact label
  match, precision measurable). Validated on real labeled telemetry (Kerberos + AWS CloudTrail).
- **off-hours** (`offhours.py`) — `entity → distribution over time-of-day`, circular statistics, a
  **soft** anomaly (partial labels, precision *not cleanly identifiable* — and that is the point:
  the architecture must represent graded evidence honestly, not only clean benchmark wins).
- **coordination** (`coordination.py`) — `two entity streams → their dependence` (mutual information),
  a **constructive existence-proof** on a synthetic mechanism-modelled corpus, **not** field-validated.
  The first family that reads *two* streams (the new binding shape) and the first whose claim is
  *constructively validated capability*, not operational validation. See its section below.

> **The tests are the source of truth.** This file is a human-readable *map* of what is validated
> and what was found; every claim below is asserted in `tests/test_fanout.py` (named inline) and the
> test wins on any conflict. Validation that isn't in a test isn't validated.

## Pipeline

```
real events → FanoutBinding → bucket_fanout (grain) → fanout_entropy → detect_fanout (conformal α)
            → fanout_verdict → DetectionVerdict → schema validation
```

The layer boundary is sharp: **this layer** owns the *semantic* bucketing (partition by entity, bin
by a chosen **grain**, project the value field); **forge-core** owns the math (`shannon_entropy`,
`conformal_pvalues`, `fdr_control`). A `FanoutBinding` is the repeated structure made data —
extracted only *after* two bindings were green, not guessed.

## What is validated (corpora: `faker-kerberos` v1, BOTS v3 CloudTrail)

Synthetic-but-realistic Windows Kerberos, 25,971 events / 30 days / 15 labeled anomalies
(`~/data/faker-kerberos/v1/`, deterministic seed 42; manifest carries Dublin Core + sha256). The
real-data tests skip if the corpus is absent.

### Fan-out family — hard anomaly, exact validation

<<<
binding                 entity → value                technique   result on real labels
PASSWORD_SPRAY          Client_Address → Account_Name  T1110.003   all 3 labeled spray IPs; 0 false positives
SERVICE_TICKET_FANOUT   Account_Name → Service_Name    T1558.003   all 4 Kerberoast accounts + 2 pass-the-ticket; 0 FP
>>>

- `test_detects_labeled_password_sprays_in_real_kerberos` — full recall, exact match (no FP) at
  grain 10 min, α=1e-3. Spray fan-out entropy ~4.3 bits sits in a clean gap above the population q99 (1.0).
- `test_detects_labeled_kerberoasting_in_real_kerberos` — the *same* detector, second binding, catches
  a whole **class**: Kerberoasting *and* pass-the-ticket share the "one account, many service tickets"
  signature. Every detection is a labeled anomaly.
- `test_fanout_verdict_is_honest_about_unattested_custody` / `test_real_spray_verdicts_are_schema_valid_and_unattested`
  — detections project into schema-valid `DetectionVerdict`s.

### Off-hours family — soft anomaly, recall + specificity (precision unidentifiable)

<<<
binding     entity         technique   gate (circular)                  result on real labels
OFF_HOURS   Account_Name   T1078       resultant_length ≥ 0.5,           recall: both labeled off-hours
                                        circular mean ∈ business hours    (jill.rhodes, jason.hahn) caught;
                                                                          specificity: 0 service accounts
>>>

- `test_offhours_recall_and_service_account_specificity_on_real_kerberos` — **recall**: both planted
  off-hours accounts caught. **Specificity**: no 24/7 `svc_*` account flagged (the circular
  concentration gate excludes accounts with no business-hours routine). **Precision is deliberately
  NOT asserted** — ~18 other flagged accounts are *unlabeled natural night activity*, real off-hours
  that the corpus simply did not plant. They are **unidentifiable, not false** — this is what a soft
  anomaly looks like, and claiming exact precision would be dishonest.
- `test_offhours_verdicts_are_schema_valid_and_unattested` — off-hours detections also project into
  schema-valid verdicts with `custody = NONE`.

### Fan-out, third binding — a NEW telemetry domain (AWS CloudTrail), same detector

Corpus: **BOTS v3** (Splunk Boss of the SOC, CloudTrail export, `~/data/bots-v3/2018/`, CC0). The
*same* fan-out machinery run over AWS CloudTrail by changing **only the loader** (`load_cloudtrail_events`)
— the test of whether the detector was Kerberos-shaped or corpus-agnostic. It is corpus-agnostic. But
the new domain surfaced two findings worth more than a green check, and the honest regime here is
**signal-validated, detection-capped** (`test_cloudtrail.py`):

<<<
binding                 entity → value                technique   result on real ground truth
cloudtrail-region-sweep userIdentity → awsRegion       T1496       web_admin swept all 15 AWS regions
                                                        (+T1078.004) (RunInstances, cryptojacking); entropy
                                                                    ≈3.9 bits, cleanly isolated. SIGNAL real.
>>>

1. **The fan-out axis is domain-specific.** In cloud-API telemetry the high-entropy fan-out is over
   **region** (the cryptojacking geographic spray), *not* over API name — over API name the attacker is
   *low*-entropy (mode-collapsed on RunInstances) while normal admins are high-entropy, so an API-name
   fan-out would invert and flag the innocents. Choosing the fan-out axis is a binding decision.
2. **Conformal needs a population; a burst does not supply one — so the detector correctly stays silent.**
   The whole attack is ~38 min → ~11 `(credential, hour)` cells, so the conformal floor `1/(n+1) ≈ 0.08`
   sits far above the same `alpha=1e-3` that works on 30-day Kerberos. The standing sweep fires on nothing
   and `web_admin` gets p ≈ 0.17 — and the detector then emits **no verdict**, refusing to assert a
   detection its calibration can't justify. The trivial `distinct-region-count > 5` baseline, which encodes
   a domain prior conformal lacks, isolates `web_admin` *exactly* (0 FP): **on this burst the baseline beats
   conformal.** Honest scope: this localizes *when* conformal earns its keep (large standing population),
   not a general win for thresholds. Proper conformal detection here needs an external normal baseline
   (per-identity history / many normal days) — *deferred*, not present in a single-burst corpus.

### Coordination family — MI over entity PAIRS, a constructive existence-proof (synthetic)

The third detector family, and the first that reads *two* streams. Mutual information catches
*coordination* (two normally-independent streams becoming dependent) where the other families catch
*single-entity collapse*. The corpus is **synthetic and self-contained** (`test_coordination.py` always
runs) — and that is a *deliberately limited* claim: **constructively validated capability**, not field
validation. It establishes exactly three things:

<<<
claim                                          how (test)
MI + FDR recovers the coordinated set exactly  3 compromised host pairs, full recall, 0 false pairs
  (synchronized multi-host beaconing)          (test_mi_recovers_the_coordinated_hosts_and_no_others)
MI beats the marginals                         per-host activity rate/entropy of coordinated hosts
  (the load-bearing claim)                     overlap the normal hosts' — no single-stream cut separates
                                               them (test_the_marginals_are_blind_to_the_coordination)
negative control                               no shared beacon → MI flags nothing (no crying wolf)
                                               (test_no_beacon_no_detection)
>>>

- **Model the mechanism, not the signature.** The corpus plants a *shared beacon schedule* (a latent
  `B_w` every compromised host follows), with each host's background tuned so its **marginal activity rate
  is identical to a normal host's**. The coordination is then a *consequence* of the modelled C2 mechanism
  (T1071), not a hand-placed MI-shaped blob — the same reason faker-kerberos's fan-out was real (entropy
  emerged from the spray). That distinction is what stops "MI beats the marginals" from being
  teaching-to-the-test.
- **FDR, not a per-cell alpha.** The O(n²) pair sweep against a clean permutation null is the
  *reduced-multiplicity discovery tier* where Benjamini–Hochberg is correct — the other half of the
  fan-out FDR finding (T0 sweeps use alpha; T1 scoped-pair discovery uses FDR).
- **What it does NOT claim:** operational value on real attacks. The signal is synthetic; ground truth is
  ours by construction. Real-data MI validation stays deferred (no adequate real corpus yet — the leading
  lead is ICS coupling-collapse; see the guarantees ledger).

## Findings (surfaced by real data, both tested)

1. **The grain is load-bearing, and guarded.** `bucket_fanout` materializes the time-bin partition,
   so changing the grain changes the artifact identity and every downstream entropy
   (`test_changing_grain_changes_the_bucketed_stream`). This is the guard against the recurring
   `c_bin → 1` collapse — if grain ever silently collapsed to the native unit, the test fails.

2. **FDR over all cells rejects nothing — FDR is a T1 control, not a T0 sweep.** The discrete
   conformal p-value floor `1/(n+1)` sits ~`1/q` times the Benjamini–Hochberg threshold `q/m` at
   m ~ 10⁴ cells, so even the most extreme cell can't pass. A T0 standing sweep uses a per-cell α;
   FDR enters at the *reduced-multiplicity* discovery tier (scoped pairs, clean permutation null).
   `test_fdr_over_all_cells_is_too_stringent_a_t0_sweep_uses_alpha`.

3. **Honest custody on unattested telemetry.** The corpus is an unsigned CSV, not attested evidence,
   so verdicts report `custody = NONE` / `trustworthiness = NONE` while the detection is still real
   (`decision = TRUE`, high score). No faked attestation — the verdict states both truths separately.

4. **Two validation regimes, both honest.** Fan-out is a *hard* anomaly — exact label match,
   precision measurable. Off-hours is a *soft* anomaly — recall + specificity are validatable, but
   precision is **not identifiable** because natural night activity is unlabeled. Representing that
   distinction (not forcing a precision number that isn't real) is the point of validating both. The
   off-hours detector also exercises forge-core's circular primitives (`resultant_length`,
   `circular_mean`), previously built-but-unused.

5. **`faker-kerberos` has no validatable coordination signal.** Its attacks are point/burst anomalies
   (the spray is a 36-second co-occurrence burst of 20 normally-independent accounts — a *clustering*
   signal, not the sustained two-entity dependence mutual information needs). MI-coordination needs a
   lateral-movement corpus (e.g. BOTS v3 Windows security) or an explicitly-labeled injected signal;
   it is **not** validated here, and forcing it would be plumbing without ground truth.

6. **Conformal-entropy has no detection advantage over `distinct-count > k` here — measured, deflating,
   recorded** (`test_baseline_comparison.py`). Held against the best justifiable baselines (not a
   strawman): spray IPs touch 20 distinct accounts, no normal IP exceeds 3, so `distinct > 5` catches all
   three sprays 0 FP — identical to conformal, at a *wider* margin (17 vs entropy's 2.7). The entropy
   feature *and* the conformal calibration are both unnecessary for detection here; the signal is fully in
   the simplest statistic. (Raw volume does *not* separate — it is the fan-out, not activity, that carries
   it.) Conformal's real value is *orthogonal to detection*: distribution-free automatic threshold
   selection + a calibrated FAR bound — not better separation. Combined with the CloudTrail burst (where
   the baseline *beats* conformal), **conformal's detection advantage is unproven on both real corpora.**
   See the guarantees ledger; proving it needs a corpus where the simple statistic does *not* separate but
   conformal does.

## Reproduce

```
uv run pytest packages/detection            # all detection tests (real-data tests skip if corpus absent)
```
