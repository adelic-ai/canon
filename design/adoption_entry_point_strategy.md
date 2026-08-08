# Adoption strategy — get in where we fit, then dissolve into position

**Status:** strategy note, 2026-06-19. Not a build plan — the *why* behind the frontends, the OFF-able
waist, and the attestation gates, framed as an adoption architecture. Captures a vision; the pieces it
names are partly built (see each), the go-to-market arc is aspirational.
**Relates to:** [ir_canonical_ruleset](ir_canonical_ruleset.md) (Sigma/KQL as lowered frontends — the rule-layer entry),
[ocsf_ingest_normalization](ocsf_ingest_normalization.md) (the OFF-able data waist — the data-layer entry),
[justified_verdict_substrate](justified_verdict_substrate.md) ("wrap any detector → receipts" — the verdict-layer
entry), [retention_and_aging](retention_and_aging.md) and [live_stream_ingest](live_stream_ingest.md)
(the scale picture), [engine_workspace_boundary](engine_workspace_boundary.md)
(multi-tenant by construction), and the standing north star: canon as the verifier half of an
LLM-proposes / canon-verifies loop.

## The problem — you don't know how they're set up

Every enterprise's stack is different and opaque from outside: you don't know their rule dialects, when
data arrives, where it lives, or in what form. So the **entry point is determined by *their* setup, not
by a fixed integration**. A rip-and-replace ("adopt our schema, rewrite your rules") is dead on arrival.
The design problem is: *meet them where they are, be useful immediately with minimal integration, and
earn the right to do more.*

## Four seams — get in where we fit

There is no single entry point; there are four, and the architecture already has a foot in each. Which is
open varies per enterprise — so expose canon at all of them, same engine behind each.

- **Rule layer.** Ingest their existing detections — Sigma now (`compile_rule`), KQL/SPL/CAR as more
  frontends — and lower them into the IR. You consume what they wrote; you never ask them to rewrite.
- **Data layer.** Meet their telemetry in whatever form via the OFF-able OCSF waist: native if that's all
  you can touch, normalized if they'll let you. Adapt to their shape, not the reverse.
- **Verdict / alert layer.** The lowest-friction seam: take the alerts they *already* produce and wrap
  them with the justified-verdict substrate (provenance, confidence, honest NONE). "Wrap any detector → an
  alert that carries its receipts." No change to their pipeline.
- **Storage / columnar layer.** Run as a job over their retained data lake (the Substrait/DataFusion
  columnar direction — comprehensive, distributed, predicate-pushed-down).

## Be useful right away — lead with the read-only entries

"Useful on day one, ~zero integration" is mostly the **read-only** seams:

- Point canon at their **rule corpus** → the coverage scorecard (real coverage, the redundancy
  bracketing, the technique gaps). Pure read, insight immediately, nothing to deploy. The Sigma
  consumption audit *is* this.
- Wrap their **alert stream** → add warrant. Read-mostly.

These buy entry without touching their firing or data plumbing. Deeper value (running detections, the
battery) needs data access — a bigger hook, more friction — so it comes later, after trust.

## Dissolve into position — the displacement arc

Not a takeover; a gradual absorption, each step earned:

1. **Read-only insight** (scorecard / wrapped verdicts) — disruption-free, immediate value.
2. **Shadow mode** — lower their rules + data into the IR, fire *alongside* their stack, show where canon
   agrees, where it adds warrant, where it finds gaps.
3. **Incremental takeover** — as the IR proves it reproduces their results, more of the
   firing/normalization/dedup moves into canon.
4. **Canon becomes the canonical layer** — their rules are one frontend lowered in; the ad-hoc stack
   dissolves from underneath.

## Attestation as the trust mechanism — what earns each step

What makes 2→4 possible *without a rip-and-replace* is the **attestation gates** (`attest_ir_faithful`,
`attest_rust_agreement`, `attest_ocsf_agreement`, and the catch-set fidelity work). They let canon make
the claim that earns the entry:

> *"I run your detections identically — provably, verdict-for-verdict — and add justification you didn't
> have."*

You displace by being **measurably faithful, plus more** — not by mandate. That is embrace-and-extend
done honestly: consume faithfully (attested), add value additively (warrant, coverage, honest NONE), earn
the right to absorb. The gates are not a technical nicety here; they are the *go-to-market wedge*.

## Honest hard parts — so this stays a plan, not a pitch

- **Heterogeneity is the cost.** "Fit anywhere" means an adapter per rule dialect and per source shape —
  the N in N×M. The IR amortizes it, but each new frontend/source is real integration work, not free.
- **Zero-integration value is mostly the read-only layer.** The moment you want to *run* detections or the
  battery, you need data access — a deeper hook.
- **Displacement is slow and trust-earned** — quarters, not demos. The realistic near-term is the additive
  warrant + coverage-insight layer; "dissolve into position" is the long arc.
- **This is a go-to-market architecture as much as a technical one.** The IR / waist / gates *enable* it;
  adoption is its own problem the code does not solve.

## One line

Consume-everything frontends + an OFF-able data waist + an additive warrant layer + attestation-as-trust =
**slot in at whatever seam is open, prove faithfulness, then absorb.** The "entry point" to design is, per
enterprise: *which seam is open here, and what's the lowest-friction useful thing we can do at it — with
the same engine behind all of them.*
