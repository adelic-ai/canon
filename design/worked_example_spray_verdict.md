# Worked example — one real detection, its whole justification walked

**The proof artifact for canon's current state (2026-06-04).** One real labeled password-spray from the
`faker-kerberos` corpus, run through the substrate, with *every* attached claim walked — what it is, and
whether it's **mechanically checked**, **honestly absent**, an **explicit assertion**, or **derived**.
Reproduce: `uv run python packages/detection/experiments/worked_example_spray_verdict.py` (needs the corpus
+ the `[rdf]` extra). The output below is verbatim.

```
DETECTION: password spray — source IP 10.3.27.24 touched 20 distinct
           accounts in 10-min bin 2954670; entropy 4.32 bits.

WHAT IT IS (the result):
  technique        T1110.003   [asserted (ATT&CK label)]
  decision         true        [MECHANICAL — kjoin(detect=TRUE, when=none) = TRUE]
  score            0.9995      [computed — LLR fusion (nominal Pd 0.9 × conformal pfa)]
WHO/WHAT/WHEN (the grounding):
  who              true        [grounded — the source IP is identified]
  what             true        [MECHANICAL — the ∃-detect]
  when             none        [ABSENT (none) — fan-out runs no temporal ∀-validate]
  where/how        none/none   [ABSENT (none) — honestly unknown]
  w_record.score   0.40        [MECHANICAL — 2/5 W's TRUE (who+what; when honestly none)]
HOW SURE / HOW SOUND (the epistemics):
  guarantee.tier   well_formed [claimed — the well_formed FLOOR (default on this path)]
  calibration      conformal FAR≤0.001 [ATTACHED — distribution-free bound]
  cross_check      true        [MECHANICAL — distinct⟷entropy agree]
  custody          none        [ABSENT (none) — unsigned CSV, honest]
  validity         none        [unchecked — no payload schema]
  trustworthiness  none        [DERIVED — kjoin(custody, validity)]
WHERE IT CAME FROM (the justification):
  provenance CID   ea60f133c555559b… [content-addressed root]
  SHACL conforms   True        [MECHANICAL — self-falsifying shapes]
```

## The artifact audited itself (this is the point, not a footnote)

The *first* version of this verdict reported `when=true` and `w_record.score=0.60`. Reviewed as an external
skeptic, that was an **overclaim**: `when` is the temporal ∀-validate fold's verdict, and fan-out runs **no
temporal recognition** — so `when` should be `none` (unanswered), not a `true` that asserts a validation
which never ran. The fix made fan-out emit `when=none`, which dropped `w_record.score` to **0.40** — *lower,
and correct*: the verdict now scores itself **down** for the timing it didn't validate, instead of up. That
is the `None`-vs-`True` discipline applied to canon's own output, and it is exactly what the substrate
exists to enforce. **A proof artifact that found and corrected its own overclaim is stronger than one that
never had it.**

## Reading the claims by class

- **Mechanically checked** (computed and falsifiable): `decision` = `kjoin(detect, when)` = `kjoin(TRUE,
  none)` = `TRUE` (detected; temporal *unvalidated*, honestly carried); `what` = the ∃-detect; `cross_check`
  = `true` (the *independent* distinct-count measure agreed with the entropy detector — had they disagreed
  this reads `both`, a soundness alarm); **`SHACL conforms = True`** (the provenance graph passes the
  self-falsifying shapes — `well_formed` is mechanically checked, not asserted).
- **Honestly absent** (`none`, never faked to `false`): `when` (no temporal fold ran), `where`/`how`,
  `custody`, `trustworthiness`. The corpus is an **unsigned CSV** — not attested evidence — so custody is
  `none` and the substrate refuses to manufacture trust. "We didn't verify the chain" is *not* "the chain
  is bad."
- **Self-scoring**: `w_record.score` = 0.40 = 2/5 W's confirmed. An unvalidated `when` and ungrounded
  `where`/`how` *lower* the grounding score — the verdict is honest about how much it actually knows.
- **Claimed / attached / asserted / derived**: `guarantee.tier` is `well_formed`, the conservative floor
  (on this bare-derive detection path it's the default claim, not a tier earned by demoting from `bounded`);
  `calibration` carries `FAR ≤ 0.001, conformal` (FAR honesty attached, not buried in the tier); `technique`
  is the human ATT&CK label; `trustworthiness` is the derived view `kjoin(custody, validity)`.
- **Computed-but-nominal**: `score` 0.9995 is an LLR fusion that rests on a **nominal Pd = 0.9** (no
  per-detector calibrated Pd) — high, but resting on one asserted input, not a calibrated probability.

## Why it's the proof

The thesis, concrete: **no result is asserted that isn't justified back to its inputs and shown on
demand** — and every honesty discipline canon exists for is visible in one verdict: the contradiction
carrier (`cross_check`/`decision` → `both` on disagreement), the absence carrier (`none`, not `false`), the
self-scoring W-record, the self-falsifying SHACL, the attached calibration — *and* the substrate catching
its own `when` overclaim. The "high-quality output on real data" goal, in one object: an alert you can act
on *because* the receipts are attached and honest. Remaining work is coverage (more detectors emitting this
same fully-justified shape) and the optional machine-checked numeric proof — not the verdict's completeness
on this detection.

## Known follow-ups surfaced by this audit

- `emit_detection_verdict` defaults `when=TRUE` (and `who=TRUE`). Fan-out now overrides `when=none`; the
  off-hours and coordination producers should be **audited the same way** — do they actually run a temporal
  ∀-validate, or are they inheriting an unearned `when=TRUE`? (Honest default would be `when=NONE` unless a
  detector asserts otherwise.)
