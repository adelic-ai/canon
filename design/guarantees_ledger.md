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
- **Fan-out, third binding — a new domain, SIGNAL validated, detection capped** (BOTS v3 CloudTrail,
  2026-06-03): the *same* fan-out detector over AWS CloudTrail, changing only the loader. The cryptojacking
  credential `web_admin` (ATT&CK **T1496** Resource Hijacking on a **T1078.004** cloud credential) swept
  `RunInstances` across **all 15 AWS regions** → near-maximal region entropy (≈ log2(15) = 3.9 bits),
  cleanly separated from every other identity (≤ 1.2 bits). **Signal validated, exact ground truth.**
  Detector reuse validated: only `load_cloudtrail_events` is new. `test_cloudtrail.py`. **But the standing
  conformal sweep does NOT fire — see CAPPED.**

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
- **Conformal is empty without a population — capped to silence on a burst, and the detector emits no
  verdict** (BOTS v3 CloudTrail, 2026-06-03). The whole attack is a ~38-min window → ~11 `(credential,
  hour)` cells, so the conformal floor `1/(n+1) ≈ 0.08` sits *three orders* above the `alpha=1e-3` that
  works on 30-day Kerberos. The standing sweep flags nothing; `web_admin` (the visual attacker) gets
  p ≈ 0.17. Correctly, the detector then **asserts nothing** — no verdict manufactured for a detection the
  calibration can't justify (the north star, applied to our own output). Same structural fact as the
  FDR-over-cells finding. `test_cloudtrail.py`.
- **Conformal-vs-trivial-baseline, first concrete data point** (answers the long-open question): on BOTS
  CloudTrail the trivial `distinct-region-count > 5` baseline isolates `web_admin` *exactly* (0 FP) where
  conformal stayed silent — so **on a burst the baseline beats conformal**, because a fixed domain prior
  needs no population and conformal's distribution-free guarantee needs one it doesn't have. This does NOT
  generalize to a win for thresholds: it localizes *when* conformal earns its keep (large standing normal
  population, as in 30-day Kerberos) vs when a domain assumption is the only thing that works (single
  burst). The trade is explicit and recorded; the marginal value of conformal *with* a population is still
  unmeasured on real data. `forge_core`/`detection.fanout.detect_by_distinct_count`, `test_cloudtrail.py`.

## DEFERRED — named, not built

- **F\*/Coq machine-checked proofs** (the polyglot path) — the only thing that lifts a decode/kernel to
  `machine_checked`. §4 of the architecture.
- **SHACL shapes** — `contracts/shapes/` is still README-only; the well-formedness fold is built but not
  domain-enforced.
- **Multi-scale** — the divisibility lattice (`forge_core/lattice.py`) is built but unused by the
  detectors; the grain-divisibility discipline beyond a single window, with the materialized-bucket
  guard, is future work. Earns its keep first at multi-scale MI (coordination cadence).
- **MI-coordination** — built primitive (`windowed_mi` + permutation null), but **no validatable corpus**,
  and the corpus search has now turned up an **emerging pattern, not just a gap** (probed 2026-06-02→03):
  three corpora examined, all show *single-entity distribution collapse*, none show the *sustained
  two-stream dependence* MI is for —
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
  **Standing observation (the durable statement):** locally-examined corpora readily furnish entropy/fan-out
  anomalies but have *not yet* furnished an *adequate instrument* for the MI experiment — let alone a target
  where joint dependence beats the marginals. The negative result to date is **instrument-limited (`None`),
  not a finding about MI (`False`)**: the experiment is unrun, not failed. **Further corpus exploration
  required** — the first adequate instrument is the goal (ICS coupling-collapse is the leading lead). MI stays
  DEFERRED; do not re-attempt on a corpus before confirming *both* a signal (increase or collapse) *and* that
  it beats the marginals.
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
