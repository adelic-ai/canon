# Verdicts as locations — the coverage-space model + the fidelity-wiring contract

**Status: design frame + wiring contract, 2026-06-18.** The frame any fidelity→verdict / fidelity→chain
build must sit inside. Matures "the W's as a coordinate system" (`web/w_coordinate_system.html`) into a
coverage-space model, and pins the guardrails so the wiring reinforces the right structure instead of
gating unnaturally. Written *before* the build, deliberately (contracts-first).

## Part A — the frame: verdicts are locations in a two-space

**Two linked spaces, bridged by the W-record.**
- **Observation space** — entity × time × feature. An anomaly is a *point* here ("something is off at this
  coordinate"). The battery's distinctive job is **surfacing these points**, including ones no rule has a
  signature for (the unknown). It is the *where-in-the-data*.
- **State space** — the kill-chain / tactic graph (states = tactics, edges = transitions; the Markov model
  and HMM-Viterbi live here). The *where-in-the-campaign*. It is a state graph.
- **The W-record is the coordinate that bridges them** — an observation's address *and* the key that places
  it into the state space via the framework (technique → tactic). Battery surfaces a point in observation
  space; the W-record locates it in state space; rules verify *at that location*; the chain is the
  **trajectory** through the state graph.

**Detectors are CO-DEPLOYED over a coverage space — not a fixed primary/corroboration hierarchy.** The
earlier "battery is primary" framing was too rigid. Battery (statistical), structural detectors (subgraph),
and external rules (Sigma) are each deployed with their own coverage strategy. A verdict's primary can be
*any* of them (the lsass subgraph is structural, not the battery; the battery may not apply at all). The
battery's *special* role is surfacing the unsignatured — not a privileged "primary" slot. Coverage is
mutual and gappy **both ways**:
- battery surfaces something no rule covers → `COVERAGE-GAP` (the orchestrator already names this),
- a rule fires where the battery was silent → the battery missed it.
Gaps are honest `NONE`s and are themselves signal.

**So a verdict = "what is true at a location,"** aggregating whatever detectors apply there as *independent
witnesses*, warrant accruing per-location. The chain (priors / future potentials / actor positioning) is the
trajectory connecting locations through the state graph. This is the coordinate-system lens made
load-bearing: **framework = the axes / state-space · battery = surfaces points · W-record = the coordinates
· rules = verify at points · verdict = truth-at-the-coordinate · chain = the path between them.**

## Part B — the fidelity-wiring guardrails (the contract)

Fidelity (per-rule coverage quality, `detection/fidelity.py`) must flow into a verdict's warrant when a rule
contributes — but the *obvious* wiring ("weight corroboration by fidelity, multiply into a score") is the
wrong one; it gates and entrenches. The guardrails:

1. **Selection by fidelity; corroboration by independence.** Fidelity picks the best detector *for each
   role* (a stronger synonym *replaces* a weaker one — selection). Only an **independent** witness (different
   mechanism / different evidence) earns a corroboration edge. A *synonym* in the corroboration slot is fake
   corroboration — the FCA/SKOS dedup already forbids it. Independence, not strength, is what makes a second
   opinion count.
   - **(correction) selection must RANK the attested, never GATE OUT the unattested.** Absence of a fidelity
     measurement is `NONE`, not low quality — at the *selection* layer too, not just corroboration. An
     unattested detector still deploys and runs; fidelity only *ranks among those with evidence*. Gating
     unmeasured detectors out of the primary slot suppresses novelty and undermines the battery's
     surface-the-unknown role — the exact entrenchment the corroboration guardrail (#5) avoids, leaking back
     in at selection. Same `absence=NONE` discipline, applied one layer up.
   - **(correction) independence is *statistical*, not structural.** The FCA/SKOS dedup catches
     *same-field-set* synonyms; it does **not** catch *correlated-but-different-fields* witnesses — two
     detectors that key on different fields yet fire on the same underlying signal. Those pass the dedup, get
     counted as "independent," and **inflate corroboration** (two votes that are really one). The honest
     notion is *measured*: low mutual information between detector outputs (canon already has the MI /
     coordination machinery). So FCA-dedup is the cheap structural pre-filter; measured independence is the
     real test. Until it's wired, corroboration counts are an *upper bound* on independent support.
2. **Additive and one-sided.** Fidelity-weighted corroboration may only *add* warrant to the primary
   detection; it must never push a verdict *below* its no-corroboration baseline. A low-fidelity witness
   makes its corroboration weaker, not the detection worse. (`NONE`≠`FALSE`; monotone-up the knowledge order.)
3. **Absence is `NONE`, never a penalty.** No high-fidelity rule for a technique → *no corroboration*, not a
   downgrade. Penalizing "no good rule available" would gate real detections behind corpus coverage — the
   unnatural gate to avoid.
4. **Carry the components; shown on demand.** The corroboration edge holds each witness *and* its fidelity
   attestation, inspectable. The aggregate is a *fold over* them, never a pre-collapsed score that hides the
   why (that breaks "justified, shown on demand" and lets gating happen invisibly).
5. **Fidelity weights the corroboration layer, not the primary decision.** Otherwise a rich-get-richer loop
   entrenches well-attested rules and makes novel/under-attested detections invisible. The primary detection
   stands independent of how good the *available rules* are.
6. **In chains: a weak/absent node is a `NONE`-gap, not a chain-break.** A low-fidelity or missing detection
   at a step leaves the chain *uncertain there*, never *broken* (treated as "didn't happen") — else real
   campaigns become false negatives.

**Unifying rule:** fidelity is a graded **additive** warrant, never a subtractive gate, and its components
stay visible. It is the same `≤_k` / warrant-is-relational / `NONE`≠`FALSE` discipline ([[project_warrant_is_relational]],
[[project_skos_graded_mapping_seam]]) applied to the coverage space.

## What's built vs. what this frame names

- **Built:** battery/structural verdicts carrying W-records (the coordinates); the kill-chain Markov model +
  HMM-Viterbi (the state space); the orchestrator's battery→tactic→forward-frontier + gaps; the registry's
  observability-gated dispatch (the start of "coverage"); the fidelity attestation (`detection/fidelity.py`,
  per-rule coverage quality).
- **Reframe / not yet built:** the explicit *coverage-space-with-locations* as the organizing structure;
  the **fidelity→verdict** wiring (the corroboration edge carrying + weighted by the witness's fidelity);
  **rules→chain** probability contribution. These are what the guardrails above constrain.

## These two corrections generalize beyond canon

They are domain-independent anti-patterns worth naming, because they recur anywhere you rank or combine:

- **Absence-gating suppresses novelty.** Any system that *selects* by a quality score which requires data
  to compute must not let *absence of measurement* exclude the unmeasured — that gates out the new and
  entrenches the already-measured. Lack of evidence ≠ low quality. (Same shape in ML model selection, search
  ranking, hiring, peer review, recommenders: the unscored must still get a turn, or the system only ever
  re-confirms what it already knows.)
- **Assumed independence double-counts.** Combining "independent" sources requires *measured* independence;
  structurally-different-but-correlated sources inflate confidence. (Ensemble ML — correlated models add no
  diversity; sensor fusion; poll aggregation; portfolio "diversification" of correlated assets.) Diversity
  must be measured, not assumed.

Both are special cases of the one rule: **a grade is an *additive, measured* warrant, never a *subtractive,
assumed* gate — and absence of a grade is `NONE`, not a low grade.**

## North-star: gather, learn, self-apply

The staging recommendation — *go get labeled corpora before building the weighted aggregation* — isn't a
detour; it's the point. **canon is a data-gathering and learning system as much as a detection one.** It
already accretes measured data about itself: fidelity attestations (what each rule actually covers), the
coverage map (the honest spectrum), the regime ledger (which primitive wins under which condition — *explicitly*
the seed for a future learned dispatch policy). The aspiration this frame serves: canon **absorbs relevant
information and applies it to itself in the right places** — measured fidelity drives selection and
corroboration-weighting; measured regimes drive dispatch; measured independence drives how votes combine. The
guardrails exist so that self-application stays honest (additive, measured, absence-aware) rather than becoming
a feedback loop that entrenches. Build the gathering first; let the application emerge from what's gathered.
