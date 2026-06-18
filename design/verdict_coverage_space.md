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
