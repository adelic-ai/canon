# canon — the through-line

**What this is.** The narrative that connects canon's technical docs: why the repo is shaped the
way it is, what was tried and dropped, and the single top-level framing everything now serves.
Orientation, not spec. When the thread is lost, start here, then go to the specs —
`self_validation_architecture.md` (the spine), `guarantees_ledger.md` (the epistemic register),
`web/detection_battery.html` (the detection design), `forge_core_step0_audit.md` (the forge port).

Written 2026-07-16. Deliberately blunt — a future reader needs the real assessment, not a
flattering one.

---

## 1. How we got here

The path was not straight, and the wrong turns are load-bearing context:

- **signalforge** began from a wrong-headed idea: treat composite Kerberos processes — long chains
  of auth failures, whole login procedures — as *signals*, run multiscale/DSP surfaces over them,
  and train ML to "learn discernment": score how likely an attack is and flag what deserves finer
  local/lateral scrutiny. It died for two reasons that still hold: discrete authentication events
  are not DSP signals at most scales, and an ML discriminator trained on data you generated yourself
  convinces no skeptic of anything.

- **CSAT / memoria** added a real insight: information theory (entropy, KL, mutual information) and
  detection theory (CFAR, CUSUM, SPRT, conformal) are genuinely useful for this problem.

- **The Semantic Web detour** added the correction to that insight: IT and DT are *not* a universal
  silver bullet. They are two disciplines with specific reach, not the method.

- **The CSAT "DSP where the data is dense" observation** is the shape of that correction: DSP earns
  its place only where discovery finds data dense enough to have a real periodicity target
  (beaconing / C2). It is a corner invoked on evidence — not a lens applied everywhere.

## 2. What died, what survived

Kept explicit so it is not re-litigated:

- **Died:** ML-on-multiscale-surfaces as the method for attack discernment.
- **Survived** — mined from signalforge as a quarry, via the Step-0 audit:
  - the divisibility lattice + hops-back walk (`forge_core/lattice.py`);
  - the DSP/DT primitives (`spectral`, `matched_filter`, `goertzel`, `filters`, `lock_in`);
  - the p-adic sampling-domain paper — a standalone number-theory/DSP result that stands
    independent of the detection framing;
  - IT and DT themselves, reframed as *one corner each* of a larger structure rather than the answer.

signalforge was not wasted. It was the quarry; the good stone came out, the framing that led there
did not.

## 3. The corrected form: the detection battery

The realization above has a concrete shape (`web/detection_battery.html`):

- A **measurement axis** (Axis A) — IT features (entropy, KL, MI), descriptive statistics (count,
  variance, Gini, cardinality/novelty), and a DSP corner (periodicity) — *feeding* a
- **decision axis** (Axis B) — DT tests (CFAR, CUSUM, SPRT, conformal) that decide "anomaly?" with a
  controlled false-alarm rate —
- behind **one output contract**: every firing returns
  `(score, W-record {who/what/when/where/how}, GuaranteeCertificate, provenance)`,
- dispatched across a **tier ladder** (T0 standing sweep → T3 adjudication), with a **rigor dial**
  (well-formed → bounded → machine-checked) orthogonal to the tier.

A named detector is a *cell*: one feature × one test, deployed at a tier. The catalog is generated
by the structure, not fixed by taste.

**forge-core is that battery's primitive layer, and further along than an early read suggests.**
It has the DT tests (matched filter, energy, Goertzel, lock-in, CFAR, CUSUM), the **IT trio
already ported** from signalforge into `information.py` (entropy / KL / MI, windowed variants, an
MI shuffle-null), the `DetectionVerdict` five-fold assembly, and — checked against the code —
**six producers wired and tested**: features `count / entropy / KL / MI / distinct-count` across the
`CFAR` and `conformal` tests, each producing a verdict that validates against the PINNED
`contracts/detection_verdict.schema.json`. The vertical slice composes across both the feature and
test axes. The real gap is Axis-A **breadth, and it is descriptive statistics, not IT**:
concentration (Gini, Herfindahl), cardinality / novelty (distinct-count, first-seen, rarity-rank)
and spread (MAD, CoV) are absent. Adding those as ops, and wiring a few more cells, is the next
step. (An earlier draft of this note said the IT features weren't ported — that was wrong; they
were. The lesson: read the code, the docs undersold it three times.)

## 4. The top-level story

Everything above serves one framing:

**The LLM proposes; canon verifies.**

The LLM — or any driver — proposes: hypotheses, detections, attack chains. Canon's job is to *verify
with warrant*: attach to every claim a justification that travels with it. The battery is *what*
canon verifies — its detection vocabulary. The semantic/provenance layer is **accountability, not
intelligence.** That is the defensible pitch, and it is stronger than "canon detects": canon's value
is that its verdicts carry their reasons.

## 5. The guardrail (the distinction that keeps getting lost)

The detection battery is the **cyber application** of canon's substrate — a demonstration that the
substrate works on one real domain. It is **not** the substrate.

The research artifact is the **domain-agnostic, warrant-carrying validator**: every concern
expressed as a graded, monotone fold over one content-addressed DAG, with the math/proof tier an
*optional deepest setting* rather than a precondition. The battery proves that on security; other
domains plug into the same contracts.

The standing risk — flagged more than once, worth flagging again — is conflating "ship the cyber
detector" (a product) with "build the validator" (the research). When in doubt: the contracts in
`contracts/` are the canon; the battery is a consumer of them.

## 6. Honest status

- The substrate approach is **sound in design.** Phases of the provenance / validation spine are
  built and tested.
- The detection battery's **vertical slice** (feature → test → five-fold verdict → PINNED
  contract) is **built and tested** for six producers (count / entropy / KL / MI / distinct-count
  × CFAR / conformal); the full feature × test grid and any foreign-data validation are not.
- **No skeptic has run any of this on data the user did not generate.** That is the bar, and it is
  unmet. Selection effects — "it works on our examples" — are not validation.

Approach-sound is a real claim. Artifact-proven is a different claim. This note asserts only the
first.
