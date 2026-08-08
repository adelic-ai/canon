# Log-integrity via consistency invariants — catching the bungled tamper (and why "what the value should be" drifts)

**Status:** design, 2026-06-20. The violation machinery exists (`detection/atom_implication.py`); designed/
learned invariants and the build-provenance pinning do not.
**Relates to:** [detection/atom_implication.py](../packages/detection/src/detection/atom_implication.py) (the implication/exclusion-violation engine this builds on),
[self_validation_architecture](self_validation_architecture.md) (the validity fold — "the anomaly malforming its own telemetry"; the Belnap
`Both` carrier), [retention_and_aging](retention_and_aging.md) (baseline drift / self-poisoning — inherited here), [ocsf_ingest_normalization](ocsf_ingest_normalization.md)
(schema impedance — inherited here at the source-schema level), [dataset_generator_product](dataset_generator_product.md) (synthcyber's
`field_profile`, extendable to field *correlations* = the learned invariants).

## The idea — a tamper is an unjustified assertion; the consistency-check is its justification test

An attacker who manipulates telemetry to evade detection makes an **unjustified assertion**: a fake field
value (`Image` rewritten from `mimikatz.exe` to `svchost.exe`). A **consistency check** is the justification
test: does that value **cohere with its correlated fields**? If `OriginalFileName` (the PE metadata) still
says `mimikatz.exe`, the assertion is incoherent → a Belnap `Both` → don't trust. This is canon's whole
argument turned on log integrity, and it is exactly the validity fold's *"anomaly malforming its own
telemetry"* case, made operational: an internal-consistency violation on a single event.

A self-consistent event satisfies its field implications; a **bungled tamper** (some fields changed, a
correlated one left stale) violates them. So the implication/exclusion lattice doubles as a tamper detector.

## Two flavors

- **Poor-discipline artifacts (free, luck-coverage).** The redundant implications that happen to span
  correlated fields (a rule testing `Image` and `OriginalFileName` for the same tool). A tamper that rewrites
  one but not the other trips it — accidental, free, sparse.
- **Designed / learned invariants (the real version).** Purpose-built field-correlation tamper-traps:
  - `Image` ↔ `OriginalFileName` — a renamed binary violates it *(this is the masquerading-detection class,
    generalized)*;
  - `ProcessGuid` coherence across an event chain — stable per process, hard to keep coherent across many
    events over time;
  - parent/child PID coherence — a spoofed `ParentProcessId` with no matching real parent;
  - `EventID` ↔ field-presence; timestamp monotonicity (backdated events).

**Unifying insight:** a whole class of evasion detections (masquerading, spoofed-parent, renamed-LOLBin) are
*instances* of field-correlation violation — and they add a detection **axis** the content rules lack: rules
catch the *attack pattern*, invariants catch the *cover-up*. So you catch the attacker who evaded the content
rule but botched the tamper.

**Caveat:** a *careful* attacker keeps all correlated fields coherent and slips through. This catches the
*bungled* one. But bungling is common, each invariant **raises the bar** (evading N invariants means keeping N
fields mutually coherent, increasingly hard across a chain), and it is free/additive.

## The hard part — "what the value should be" is a moving target

The whole approach needs a notion of the **expected** value or correlation, and you **cannot hardcode it**,
because the ground truth drifts:

- **Windows updates / patches** change a binary's version resource, hash, even its `OriginalFileName` between
  builds. The "canonical `OriginalFileName` for `svchost.exe`" is not a constant — it's per-build.
- **Microsoft schema changes** (Sysmon versions, ETW providers) add / remove / rename **fields** — so even the
  *shape* of the event drifts, not just the values (the OCSF/normalization impedance, at the source-schema
  level).
- **Non-patch feature updates / out-of-band changes** move the target without a tidy version bump.

So a hardcoded "expected value" invariant would false-positive on every legitimate update. The honest handling
follows canon's thesis — *don't assert a "should be" you can't justify*:

- **Learn it per-environment, don't hardcode.** Extend synthcyber's `field_profile` from field *distributions*
  to field *correlations* over **this environment's clean telemetry** → the invariant tracks the actual build
  state, not a universal constant. A tamper is then a deviation from *local* coherence, not from a global
  canon.
- **Pin the invariant to its build/schema provenance.** Each learned invariant carries the environment state
  it was learned under (OS build, Sysmon/schema version) in the workspace manifest. On an update it is
  **re-validated / re-learned** — the invariant is a *versioned, drifting baseline*, not a fixed truth (same
  shape as the retention/aging baseline).
- **Tolerance-as-set, not point.** Where cross-build knowledge exists, "expected" is the *set* of known-good
  values across builds, not a single value — a deviation must fall outside the whole set.
- **Honest NONE where unknown.** If there is no confident baseline for a field's expected value (new binary,
  unseen build), a deviation is **NONE (can't say)**, not `Both` (tamper). Never flag a tamper you can't
  justify — the same NONE≠FALSE discipline.
- **Inherits the drift caveats.** Learned coherence has the conformal/baseline soft spots
  ([retention_and_aging](retention_and_aging.md)): a legitimate update reads as a violation until the baseline catches up, and a
  slow-burn attacker could poison the learned invariant. So invariant violations escalate to `Both`
  (held/investigated), not auto-FALSE — and learned invariants exclude flagged events from their own updates.

## Wiring & status

- **Built:** the implication/exclusion-violation engine (`atom_implication.consistency_violations`) — the
  mechanism that turns a coherence failure into a `Both`.
- **Not built:** the designed field-correlation invariants; learning them from clean telemetry (the
  `field_profile` → field-correlation extension — the *second payoff* of the data-fetch + synthcyber grounding
  work); the build/schema-provenance pinning + re-validation; the validity-fold wiring (carry the deviation —
  *which* fields are incoherent — as the fold already does for schema-malformedness).
- **Honest scope:** a content-coherence layer that catches *bungled* tampers and raises the evasion bar — not
  a defense against a careful attacker, and only as good as the *learned, build-pinned, NONE-honest* baseline
  of what coherence should hold.
