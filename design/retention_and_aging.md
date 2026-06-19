# Retention and aging — what survives when the raw telemetry is gone

**Status:** design, not built. Captured 2026-06-19 from the live-macOS thread.
**Relates to:** [[engine_workspace_boundary]] (retention is workspace state, not engine code —
this fills the lifecycle gap that doc left open), [[verdict_coverage_space]] (past the horizon
is a NONE, not a FALSE), [[self_validation_architecture]] (justification-is-the-object;
feed-liveness = custody; the §9 distribution-shift risk), [[justified_verdict_substrate]] (the
verdict is what survives), [[skos_graded_mapping_seam]] / [[ocsf_ingest_normalization]] (the
ingest that feeds this).

## The problem

A continuous monitor over a forgetful source (macOS Endpoint Security / `eslogger` retains
**nothing** — it streams live and drops each event the instant it's emitted; see
[[ocsf_ingest_normalization]]) accumulates raw events without bound. You cannot keep the
firehose. So the real question is **not "how long do we keep raw events" but "what do raw
events get folded into before we drop them, and how do we stay honest about what we can no
longer reconstruct."**

The source forgets immediately. Retention is entirely the workspace's job. canon's
contribution over a normal SIEM's retention policy is two things a SIEM doesn't do:

1. **Surviving verdicts carry their own justification**, so they don't rot when their inputs
   are deleted.
2. **The retention horizon is an honest NONE boundary**, recorded, not a silent wall.

## The lifecycle — raw shrinks into derived

```
hot  (trailing window, recent raw)  ──fold──▶  warm (cells + baselines + verdicts)  ──age──▶  cold (verdicts + materialized provenance only)
     the battery computes here                 raw rows dropped, statistics kept             re-derivation impossible → queries = NONE-bounded
```

Three things survive aging, in increasing compression:

### 1. Verdicts — but only if justification is *materialized*, not *pointed-at*

The load-bearing architectural commitment: "justification is not metadata — it is the same
object as the result" ([[self_validation_architecture]] §1). Operationally that becomes a
retention rule:

- A verdict that **embeds** its receipts (the matched fields, the W-record, the cell
  statistic — content-addressed) survives the raw events aging out.
- A verdict that merely **points into** a log that later rolls becomes an *unjustifiable
  assertion* the moment that log is deleted — the exact failure canon exists to prevent.

So the aging policy forces materialization: **when a raw event is load-bearing for a verdict,
its relevant fields are promoted into the verdict's provenance before the raw row becomes
collectible.** In content-addressed-DAG terms this is Merkle GC — pin-and-sweep, a named
wheel: verdicts are pin roots; a raw node still reachable from a live verdict is pinned (not
swept, even past the horizon); raw nodes unreachable from any pin root and past the horizon
are collectible. Verdicts + their materialized provenance get the longest retention because
they are small and the highest-value forensic record.

### 2. Baselines — the fold of raw into "normal"

The battery's value *is* a calibrated model of normal ("this host's `xpcproxy` fans out to
~13 children"). That model is the compression of the raw stream: keep the calibration, drop
the events that produced it. The intermediate form is the **aggregate cell** (the
`FanoutCell` — per-(entity, time-bin) statistic), not the raw rows: aging-down rolls raw
events into cell statistics, retains cells, drops rows — another order of magnitude smaller,
still enough to compute rarity against. Baselines + cells get medium retention.

### 3. Past the horizon — NONE, not FALSE, and the horizon is recorded

Once raw (and then cells) are gone you cannot re-derive or re-query over that window. A
question asked today about last month is a **coverage NONE** (telemetry aged out), never a
clean FALSE — the same discipline as a live-feed gap, which is *also* a NONE
([[verdict_coverage_space]]). So:

- The retention horizon is a **first-class, recorded coverage boundary**: "answerable back to
  date X; before X is NONE." Not a silent wall.
- A feed gap *within* the retention window (monitor was down) is likewise a NONE for that
  window — and a live, unbroken feed is intact chain-of-custody, so feed-liveness =
  custody supplies exactly this signal ([[self_validation_architecture]] §6).

## Aging is also *desirable* — and it is the flagged risk

Aging is not only storage management; it is **relevance**. You *want* the baseline to forget
old behavior so "normal" tracks the current environment — a binary that was rare six months
ago and is now ubiquitous should stop alarming. The sliding reference window is what keeps
the calibration current.

But this is precisely the architecture's flagged soft spot — *conformal / baseline under
distribution-shift and contaminated reference is unsolved* ([[self_validation_architecture]]
§9). Two concrete hazards:

- **Self-poisoning.** A slow-burn attacker who ramps gradually gets folded into "normal" as
  the window slides. *Mitigation:* exclude flagged-anomalous and `Both` cells from baseline
  updates — do not let the thing you are hunting calibrate the hunter.
- **Drift false-alarms.** Legitimate environment change reads as anomaly until the window
  catches up.

Neither is solved. Both must be **recorded assumptions** on any baseline-derived verdict (the
per-result guarantee tier demotes when the reference window is contaminated or suspect), not
papered over.

## One more survivor — the `Both` queue, retained before it ages

The rare, contradictory (`Both`), or flagged cells are the **highest-value things to retain
longer and label**, precisely because they are what the baseline would otherwise forget. They
go to the active-learning / acquisition queue before aging out — the BOTH-acquisition idea
([[justified_verdict_substrate]], the restart note's Phase-2 self-improvement loop). Aging a
flagged cell into "normal" silently is the worst case; promoting it is the best.

## Scope / open

- **Built:** nothing here. The streaming reader, the workspace store, and the GC/fold policy
  do not exist yet; this records the design before the build (the same discipline as
  [[verdict_coverage_space]]).
- **The fold-then-drop step** (raw → cells) needs the `FanoutBinding`-style source binding for
  the live stream to exist first.
- **Materialization-on-pin** (promoting a load-bearing raw event's fields into a verdict
  before GC) is the one genuinely new mechanism; the rest is pin-and-sweep + windowed
  recompute, both named wheels.
- **Retention horizons are workspace config**, recorded in the manifest
  ([[engine_workspace_boundary]]): `{hot_window, warm_horizon, cold_keeps_verdicts}` per
  source. Multi-tenant by construction — different engagements keep different amounts.
