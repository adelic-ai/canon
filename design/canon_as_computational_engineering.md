# Canon as computational engineering — logic as the physics of inference

**Status:** EXPLORATION / vision synthesis, 2026-06-21. Captures a strategy thread: is canon on the Leap71
"computational engineering" trajectory, what would put it there, what formal apparatus it should build on
rather than reinvent, and what it can realistically beat. Not a spec — a map of where the program is headed.
**Relates to:** [self_validation_architecture](self_validation_architecture.md), [warrant_is_relational](warrant_is_relational.md),
[detection_ir_motif_ontology](detection_ir_motif_ontology.md),
[engine_workspace_boundary](engine_workspace_boundary.md), [ir_vocabulary_stratification](ir_vocabulary_stratification.md),
[grounded_fidelity_bots_real_benign](grounded_fidelity_bots_real_benign.md),
[resolution_axes_exploration](resolution_axes_exploration.md). Two framings it leans on are not
written up as documents here: canon as the verifier half of an LLM-proposes / canon-verifies loop,
and the abduction loop in which uncovered anomalies become detection candidates.

## The reference — Leap71 / computational engineering

Leap71 doesn't CAD a rocket engine. It encodes the *engineering reasoning* (physics, design logic) into a
computational model (Noyron) that **computes** the full geometry from requirements. The aerospike fired on
first test — "first-time-right" — because the physics is encoded faithfully, not approximated by intuition.
The inversion that matters: **the model is the asset, not any one engine.** Build the reasoning engine; it
generates unlimited, traceable designs. (Not ML — physics-as-computation, deterministic and inspectable.)

## Key components of a computational-engineering structure (and canon's standing)

1. **Encoded reasoning, not artifacts — the model is the asset.** canon: STRONG — the engine generates
   verdicts, not a pile of alerts.
2. **A composable, faithful kernel.** canon: the IR / atom-basis + the provenance DAG + the faithfulness gates
   (emit→attest, Rust-agreement). The "atoms as kernel, evaluate once, compose" move is this. MATCH, maturing.
3. **First-principles grounding.** canon: a first-rate analytic foundation (the formal sciences) + empirical
   reality — but **no closed empirical LAW** of the phenomenon (the divergence, below). The foundation is deep
   and peer-to-physics; only the empirical-constraint layer is harder.
4. **Determinism + full traceability — every output explains itself.** canon: the justified-verdict substrate;
   the warrant travels *fused* with the result. **STRONGEST alignment — arguably ahead of what the analogy
   even needs.**
5. **Requirements → model → output, model reusable across instances.** canon: the engine/workspace boundary
   (engine universal, workspace per-engagement). DIRECT MATCH.
6. **A closing verification loop — the "test stand".** canon: grounded validation on real labeled data —
   expensive, partial, data-limited. **THE BOTTLENECK** (and the credibility-maker).
7. **Abstraction to a domain-agnostic core.** canon: the kigumi / standalone-validator goal. IN PROGRESS.

## The crucial divergence — there is no predictive physics of intrusion

Leap71 has physics → first-time-right + a *cheap, definitive* test (fire the engine). Cyber detection has no
closed, predictive theory of "is this an intrusion" — its "physics" is logic (sound) + empirical, **adversarial**
reality (messy, no closed form). Two consequences set the real targets:

- **"First-time-right" → "honestly-warranted."** Canon cannot be correct-because-physics. Its achievable analog
  is *the verdict carries its warrant and its uncertainty truthfully.* Don't chase a certainty the domain can't
  give; chase honest, calibrated, traceable warrant — which the substrate already does.
- **The test stand is the credibility-maker, and it is the bottleneck.** Leap71 was believed because the engine
  fired. Canon is believed when computed detections demonstrably catch real attacks while staying clean on real
  benign — grounded validation. **This is why the data work (`bots-v3`) is not a side-quest; it IS the engine
  test stand.** Build toward firing the engine cheaply and often.

## Two deep foundations — the formal sciences (analytic) and empirical reality (contingent)

Do **not** read the formal apparatus as a mere *lens* for processing data — that subordinates it, and gets the
dependency backwards. The formal sciences are not downstream of physics; **physics is downstream of them**
(Newton built calculus for mechanics; Riemannian geometry preceded GR; Hilbert spaces preceded QM; the
mathematical structure routinely sources the physics). Logic and its family are a deep continent in their own
right — proof theory, model theory, set/category theory, computability, the foundations edifice — explored as
deeply as physics and **prior** to it in the order of foundation.

The family canon stands on, each member load-bearing: **logic** (propositional/modal/temporal/many-valued
Belnap/non-monotonic — the carrier + entailment); **order & lattice theory, FCA, Galois connections** (the SKOS
lattice); **information theory** (tightness/entropy/KL/MI); **probability, statistics, measure theory**
(calibration, the abductive posterior); **type theory, category theory, computability** (the IR, composition,
emitters); **decision & game theory** (the adversarial axis — the attacker *chooses*; SPRT is decision theory);
**proof & model theory** (warrant-depth / machine_checked).

The distinction between this family and physics is **not depth — it's mode of warrant.** The formal sciences
give *analytic / necessary* truth (true by derivation, in all possible worlds — `Γ ⊨ φ`); physics gives
*synthetic / contingent* truth (the world happens to be this way). Both deep, different *kinds* of truth — and
this is exactly canon's own warrant-is-relational split (entailment exact, empirical graded). So canon stands on
**two** deep foundations: the analytic family (necessary, prior, first-rate) *and* empirical grounding
(contingent — the data/test-stand). Physics is one fusion of a deep analytic structure with a *clean* empirical
law; canon is another fusion of the *same* analytic bedrock with a *messier* empirical constraint (adversarial,
no closed law). The foundation isn't second-tier; only the empirical-constraint layer is harder.

> So the corrected one-liner: canon does **not** lack physics — it has the foundational theory physics itself is
> built on, and keeps the necessary (proof) and contingent (data) warrants cleanly distinct per node. What it
> lacks vs physics is a *clean empirical law*, not deep theory. Build on the established formal tools (below);
> ground them on real data (the test stand). Two foundations, both first-class.

## What canon is circling — the detection vision

- **The "wands" / atom basis.** Spray-and-pray = ~3700 independent rules. Factor them into the small set of
  shared **atoms** (predicate × field) they are built from (`atom_index`: ~427 concepts → fewer atoms).
  **Evaluate the atom basis ONCE over a log → a content-addressed atom-truth artifact → every known rule is a
  boolean composition of already-computed atom-truths, data-free.** Finite + complete *for the known corpus*
  (not "every possible detection" — new techniques mint new atoms).
- **Two inference modes.**
  - **Deductive** — fire atoms → entailment → *definitive* detections (what's *there*). True/false. (This is a
    Datalog program; see tools.)
  - **Abductive** — partial / weak signs across long timeranges → posterior **P(intrusion)** over the kill-chain
    graph (low-and-slow; what's *likely*). The probabilistic honest-NONE: not "clean," but "P(intrusion)=x, and
    here are the partial signals that warrant it." **Discrimination = COHERENCE** (entity-linked, causally
    ordered, crown-jewel-directed), NOT signal *count* — else it degenerates into SIEM risk-scoring.
- **Composition over the attack-graph.** Definitive detections pin nodes hard; abductive accumulation fills the
  rest with graded belief; crown-jewel-directed paths are where you read off "likelihood of intrusion *here*."
  Detections factor along shared graph-edges the way rules factor into shared atoms — **two factorings, same
  shape.**

## The resolution axes — the analysis structure being refined

Resolution = the power to distinguish genuinely-different and merge genuinely-same, rising **claim → structure →
behavior**. The five (from the resolution-axes exploration): (1) what a rule detects
[tag→FCA→content_signature→catch-set]; (2) how rules relate [dedup→SKOS→tightness→co-catch]; (3) the carrier
[boolean→Belnap]; (4) cross-schema mapping [exact-or-nothing→SKOS-graded + load-bearingness gate]; (5) why a
rule missed [silent→typed cause→assembly-level].

Two axes the five miss (they're all *static* and *input-side*):
- **Trajectory / temporal** — point-event → sequence → kill-chain-with-HMM. Canon has `killchain`/`hmm`; this
  is the time dimension.
- **Warrant-depth** — absent → well_formed → bounded → machine_checked. Distinguishes "guessed anomaly" from
  "proven anomaly" (same string, different backing). The substrate's spine; the *output/verdict* side the five
  under-cover.
- (weaker: adversarial-robustness; coverage/blindness.)

Live refinements, ranked: **cross-corpus ablation** (run the treatment over N corpora, diff result-CIDs — what's
stable is *structure*, what moves is the *instance*) and **catch-profile** (record *why* each instance fired,
not just *which* — makes corroboration-by-independence measurable). content_digest is a cheap proxy-polish
(low leverage — the behavioral layer overrides it); "don't collapse the two verdict axes" is a maintained
invariant.

> **The treated corpus is an INSTANCE** — warrant-is-relational turned inward. But only the BEHAVIORAL/catch-set
> layer is the instance; the STRUCTURAL treatment is *portable* (corpus-free). Invest machinery on the portable
> structural half (free wins); behavioral resolution is data-bound. Cross-corpus ablation is what *measures*
> which is which — and it doubles as the honest-scoring mechanism for any learning loop.

## The ML loop — the realistic version

ML doesn't invent structure; it **searches a space you frame, scored by a metric you ground.** The buildable
loop: a generative proposer (Fable 5) emits candidate refinements/axes → apply each → **score by the two-sided
fidelity delta on a HELD-OUT / cross-corpus background** → keep improvements. Propose-verify, with
`grounded_fidelity` as the verifier. **Cross-corpus scoring is what keeps it honest** — else it teaches to the
test (the same circularity as two-instances-one-driver). The framing (what is an axis, what is the metric)
stays human; ML automates the search.

## The formal toolbox — don't reinvent the wheel

Mapped to canon's actual needs:

- **Deductive inference at scale** → **Datalog** (the atom→entailment engine *is* a Datalog program;
  **Soufflé** is the fast, battle-tested engine, used in security/program analysis). **MulVAL** —
  logic/Datalog **attack-graph generation** — is a *direct precedent* for the compound-multi-path-to-crown-jewels
  idea.
- **Abductive / partial-chain** → **Abductive Logic Programming**; **ASP (clingo)**; **defeasible logic**
  ("not compromised, but P high" that can flip with new evidence).
- **Evidence accumulation over time** → **SPRT** (Wald — provably-optimal "accumulate until the likelihood
  ratio crosses a bound," exactly partial-chains-over-long-timeranges); **Bayesian networks / PGMs** (the
  general form of the kill-chain posterior; the HMM is a special case); **CUSUM** (using).
- **Calibration** → **conformal prediction** (already using — the right distribution-free tool).
- **Temporal / trajectory pattern-matching** → **temporal logic (LTL/CTL)** + **complex event processing**
  (Siddhi/Esper). A kill-chain *is* a temporal-logic formula over events.
- **Consistency / verification (warrant-depth)** → **SMT (Z3)** (`atom_implication.consistency_violations` is a
  hand-rolled poor-man's SMT); **proof assistants (Lean/Coq/F\*)** — the machine_checked top, deferred.
- **Causation vs correlation (attribution)** → **Pearl SCMs / do-calculus** (caused-by-attack vs coincidental;
  the coherence-not-count discrimination).
- **Evidence + explicit ignorance** → **Dempster-Shafer** (belief vs plausibility — tempting for honest-NONE,
  but contested; Bayesian + explicit NONE mass is probably cleaner). Know it, be wary.
- **Ontology reasoning** → **DL reasoners (HermiT/ELK over OWL)** if the SKOS/OWL work grows teeth.

**Shortlist if nothing else:** Soufflé (Datalog), MulVAL (attack graphs), SPRT (accumulation), Z3
(consistency), LTL + CEP (trajectories).

## The goal — better than the median cyber engineer, without ML

Achievable on the dimensions where **formal rigor beats human inconsistency**: consistency (no forgotten edge
cases), coverage-honesty (NONE not FALSE — knows where it's blind), calibration (likelihoods, not gut), and
traceability (shows its work). Median detection practice is inconsistent, over-claims, sprays-and-prays 3700
rules, and doesn't calibrate. A sound logical+statistical engine beats that *structurally* — and that's a large
fraction of the actual job.

**Not** achievable without the generative half: novelty (a technique nobody encoded), org-context (this site's
weird-but-benign), adversarial creativity (the next move). So the honest claim is **beats the median on
execution, not creativity** — exactly the Leap71 pattern (Noyron out-*executes* the encoded physics; it doesn't
out-*create* the engineer). "Without ML" is coherent for that reason: Noyron isn't ML either — it's
physics-as-computation; canon's analog is logic-and-statistics-as-computation.

## Everything reduces to two bottlenecks

Across the wands, the abductive posterior, the ML loop, and the resolution axes, it all reduces to the same two
things: a **generative proposer** (Fable 5 — the imagination) and a **grounded metric on differently-shaped
data** (the test stand — the data-shape problem). The analytic foundation (the formal sciences) is first-rate and
mostly in hand; these two are how the *other* foundation — the empirical one — actually gets built. **Build the
test stand; you already have the bedrock.**
