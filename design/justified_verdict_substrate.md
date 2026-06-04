# The uniform justified-verdict substrate — every alert carries its receipts

**The crystallization of canon's current state (2026-06-04).** The detector battery is a *vehicle*; this
is the thing it demonstrates and the thing of value. In a traditional SIEM the justification for an alert
*exists* but is scattered (rule in one place, author in git, data lineage in a pipeline config) and the
*epistemic* parts — confidence calibration, feed integrity, the assumptions, whether two independent
measures agreed — are written down **nowhere**, left to an analyst to reconstruct. Canon makes the
justification a **fold of the same content-addressed object as the result**: it travels *with* the alert,
machine-readable, walkable on demand from one provenance CID.

## The claim, scoped honestly

> **The substrate uniformly *carries* honest, fully-attached justification for any detector's output —
> shape standardized, content preserved.** It does *not* yet prove every attached check is operationally
> valuable (the cross-checks' *mechanics* are wired; whether a `both` catches a real problem is deferred).

## Shape standardized, content preserved (the abstraction boundary)

Every verdict has the **same slots** (the `detection_verdict.schema.json` contract): `decision` · `score` ·
`w_record` (the five W's) · `guarantee` (the earned tier) · `custody` · `validity` · `trustworthiness` ·
`cross_check` · `calibration` · `provenance` (CID). But each detector **earns those slots by its own
mechanics** — the substrate never forces one cross-check or one calibrator on everyone:

<<<
family        cross-check (independent measure)        calibrator
fan-out       distinct-count ⟷ entropy                 conformal (FAR ≤ α)
off-hours     conformal rarity ⟷ literal off-hours     conformal (FAR ≤ α)
coordination  MI ⟷ Pearson correlation                 FDR (level q, Benjamini–Hochberg)
>>>

That is the right boundary, and the failure mode it avoids: *"every detector must use the same check"*
would be a leaky abstraction. *"every detector must carry a check, earned by its own mechanics"* is a
narrow waist — one stable interchange, content varying freely above it. Worked examples:
`packages/detection/experiments/worked_example_spray_verdict.py` (fan-out) and
`worked_example_coordination_verdict.py` (coordination — the most different: FDR + MI⟷correlation).

## Detector-agnostic — why the substrate is the transferable capability

`assemble_verdict` / `emit_detection_verdict` know nothing about fan-out or MI; they take *any* detector's
outputs and produce a justified verdict. So the deliverable is not "canon's three detectors" — it is
**"wrap any detector → an alert that carries its receipts."** The three families are the *proof the
substrate generalizes*, not the product. This is the cleanest answer to research-vs-product: the
product-like core is this substrate, already separable from the specific detectors.

## The honesty disciplines, visible in one verdict

- **`None` vs `False`** — an unanswered claim is `none`, never a faked `false` ("we didn't check" ≠ "it's
  clean"). Custody on an unsigned corpus is `none`; trustworthiness derives from it; the chain is not faked.
- **Earned-only `when`** — the temporal ∀-validate verdict defaults `none`; a detector claims `when=true`
  *only* by actually running a temporal check. The audit that found and propagated this fix across all
  producers is the defining capability: **a system that caught its own unearned assertion.**
- **`Both` as a soundness alarm** — `decision` and `cross_check` fuse independent paths with `kjoin`;
  disagreement surfaces as `both`, not an averaged-away middle.
- **Earned, demotable guarantee tier** — the tier a result gets is computed from what held on its input,
  capped at the unattested floor, not asserted.
- **Self-falsifying provenance** — the verdict's PROV-O graph is SHACL-validated (`well_formed` is
  *checked*, not claimed); a malformed graph fails and the violation is surfaced.
- **Self-scoring grounding** — `w_record.score` *lowers* itself for W's it didn't ground (an unvalidated
  `when` and ungrounded `where`/`how` make a detection score *down*, not falsely up).

## What's demonstrated vs deferred

- **Demonstrated:** the substrate carries the uniform honest shape across the whole battery, on real
  (fan-out/off-hours) and synthetic (coordination) data; the justification is attached and walkable;
  the honesty disciplines are mechanical, including the substrate catching its own overclaim.
- **Deferred (named, not hidden):** the cross-checks' *operational* value (does a `both` flag something
  real?); the machine-checked numeric proof tier (an honest recorded-absence today); MI's operational
  value on real coordination data.

The milestone is **"uniform, honest, attached justification, detector-agnostic"** — not "all of it
operationally proven." Keeping that line is itself the thesis.
