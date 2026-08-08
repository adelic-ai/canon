# The detection-corpus treatment pipeline — a provenance-tracked recipe (and the product it produces)

**Status:** design, 2026-06-20. Formalizes the *process* we used (ad-hoc) to consume Sigma into a fixed,
content-addressed, provenance-recorded **pipeline**, so any end-result knows the state that produced it and
can be improved by ablation. Stages 1–3 are built; stage 4 (the lattice) is the next build; stage 5
(catch-set) is gated on labeled data (path below).
**Relates to:** [skos_graded_mapping_seam](skos_graded_mapping_seam.md) (stage 4 = the SKOS-graded lattice), [ir_canonical_ruleset](ir_canonical_ruleset.md)
(the IR + frontends), [detection/audit.py::consume_sigma](../packages/detection/src/detection/audit.py) (stage 3 scorecard), [per_ttp_coverage_layers](per_ttp_coverage_layers.md) (stage 6),
[detection/fidelity_scorecard.py](../packages/detection/src/detection/fidelity_scorecard.py) / [dataset_generator_product](dataset_generator_product.md) (stage 5), [engine_workspace_boundary](engine_workspace_boundary.md) (the manifest),
[self_validation_architecture](self_validation_architecture.md) (provenance — this is canon dogfooding its own substrate on its own process).

## Why formalize the process

We treated Sigma this session as a sequence of one-off moves (audit → fidelity → content-signature → atom
factoring → entailment → cross-check validation). The *output* is valuable, but it wasn't **reproducible**
(no record of what corpus/code/labels produced it) or **improvable** (no way to swap a step and measure the
delta). Formalizing turns the process into a **recipe**: a fixed sequence of content-addressed stages, each
pinned to its inputs, so the end-result carries provenance and the recipe itself is a tunable object.

This is canon's own provenance substrate turned on its own process — the most honest demonstration of the
thesis: *no result asserted that isn't justified back to its inputs.*

## The pipeline

```
0 ingest+PIN ─▶ 1 compile→IR ─▶ 2 structural-verify ─▶ 3 categorize (lattice) ─▶ 4 ground (catch-set) ─▶ 5 coverage ─▶ 6 report
   corpus@cid      eval subset     faithful firing         SKOS graded edges        which rules co-catch      per-TTP        the artifact
```

Each stage takes the prior content-addressed output + its own pinned inputs, and emits a content-addressed
artifact. "Asserts" = the claim the stage earns; "status" = built / next / gated.

- **0 · ingest + pin** — clone the corpus at a pinned commit; record `corpus@cid`. *Asserts:* exactly which
  rules. *Built (path-ref'd corpus).* **Source-agnostic:** Sigma now; CAR / KQL / SPL enter here as alternate
  frontends, each lowering to the same IR at stage 1.
- **1 · compile → IR** — `compile_rule` over the evaluable subset → typed `CompiledRule`s. *Asserts:* the
  firing logic, normalized. *Built* (~58–99% per construct; reason-histogram = the IR-breadth roadmap).
- **2 · structural-verify** — `attest_ir_faithful` / `attest_factored_agreement` / `attest_entailment_agreement`
  / `attest_rust_agreement`: every engine computes what the rule means. *Asserts:* faithful evaluation.
  *Built, attested.*
- **3 · categorize (the lattice)** — the **SKOS-graded structural relation** between rules
  (`exactMatch`/`broadMatch`/`narrowMatch`/`relatedMatch`), earned by contents (clause-set ⊆, content_digest),
  with a callable `.why()`. Generalizes `admission.structural_relation` across the corpus. *Asserts:* the
  graded relation (dedup = the `exactMatch` slice; the rest is navigable order). **NEXT — corpus-free, not
  gated** (see [skos_graded_mapping_seam](skos_graded_mapping_seam.md)).
- **4 · ground (catch-set)** — run rules against **labeled** instances → per-rule `caught_on: [instance_cids]`;
  group rules by co-caught sets = true catch-set membership; verify tags claim-vs-catch. *Asserts:* what each
  rule *actually* detects (the only behavioral ground). **GATED on labeled data** — path below. Upgrades the
  stage-3 edges from claimed (structural) to grounded (behavioral); the keystone.
- **5 · coverage** — the per-TTP layered decomposition (atoms → compositions → catch-classes), bounded by the
  stage-3/4 keys. *Asserts:* what's covered, what's a gap, redundancy as bounds. *Partial.*
- **6 · report** — the content-addressed artifact: every rule + IR + structural verdict + graded edges +
  catch-set (where grounded) + coverage, all CID-addressed with provenance. *Asserts:* the whole treatment,
  reproducible. **The product.**

## The manifest — the recipe's provenance

A run is pinned by a manifest, so the end-result knows its producing state:

```json
{ "recipe": "detection-treatment@v1",
  "corpus":   { "source": "sigmahq", "commit": "<sha>", "cid": "<cid>" },
  "code":     { "canon_commit": "<sha>" },
  "labels":   { "datasets": ["otrf@<sha>", "evtx-attack-samples@<sha>", "synthcyber@<sha>"], "cid": "<cid>" },
  "stages":   ["ingest","compile","verify","categorize","ground","coverage","report"],
  "result":   "<artifact-cid>" }
```

Consequences (the two asks): **reproducible** — same manifest → same `result` CID (re-run reproduces it
exactly); **improvable** — swap one stage (a better lattice metric, more labels), re-run, **diff the two
result CIDs** to measure whether the treatment improved. That diff-the-artifact loop is the ML-ish
ablation/experiment loop, with provenance instead of vibes ([regime_ledger](regime_ledger.md) / the canon-improves-itself
thread).

## The catch-set grounding path (stage 4) — gated, not blocked

Stage 4 needs labeled instances across many techniques. Two sources, used together:
- **Real, open, technique-labeled telemetry** (survey, 2026-06-20): clone, by priority, **OTRF
  Security-Datasets** (JSONL, `_metadata.yaml` ATT&CK labels — same family as the LSASS sample), **EVTX-to-MITRE-Attack**
  (270+ per-technique, + Linux/cloud), **EVTX-ATTACK-SAMPLES** (canonical; needs an EVTX→JSON step),
  **splunk/attack_data** (per-`T####`), **hayabusa-sample-evtx** (curated to exercise Sigma). These fix the
  "one campaign = one channel" denominator that made the T1003.001 fidelity misleading. (Verify licenses on
  clone; GPL-3.0 for OTRF; data is for local grounding.)
- **synthcyber** synthetic, correct-by-construction labels: built + grounded for T1003.001 only; extend to
  3–5 more high-value techniques + add `detection/catch_set.py::group_by_catch_set` (the fidelity machinery —
  `attest_fidelity`, `grounded_fidelity` — already exists and is waiting for labels).

So the gate is *acquire-and-extend*, not *invent*. Until grounded, the report honestly carries catch-set as
NONE for un-labeled techniques and falls back to the stage-3 structural keys.

## The product

An MIT-licensed repo: **the fully-treated detection corpus** — every rule as IR + structural verification +
the SKOS-graded relation graph + catch-set grounding (where labels exist) + per-TTP coverage, content-addressed,
provenance-carrying, source-agnostic (Sigma now, CAR/others as frontends). Nobody has a *grounded, categorized,
verified* detection corpus; the artifact and the recipe that produced it are both the deliverable.

## Status

- **Built:** stages 0–2 (ingest/pin, compile→IR, structural-verify), the fidelity machinery (stage 4 engine,
  awaiting labels), content-signature (the `exactMatch` slice of stage 3).
- **Next (this branch):** stage 3 — the SKOS-graded rule-relation lattice (corpus-free), as the first
  provenance-recorded stage; and the **manifest + recipe orchestration** so it's born provenance-tracked.
- **Gated:** stage 4 catch-set (acquire labeled data + extend synthcyber + `catch_set.py`).
- **Partial / later:** stage 5 coverage report; stage 6 the published MIT artifact; CAR/others frontends.
