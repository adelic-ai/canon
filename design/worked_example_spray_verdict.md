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
  technique        T1110.003          [asserted (ATT&CK label)]
  decision         true               [MECHANICAL — kjoin(detect, when)]
  score            0.9995             [MECHANICAL — conformal p-value]
WHO/WHAT/WHEN (the grounding):
  who              true               [grounded — the source IP]
  what             true               [MECHANICAL — the ∃-detect]
  when             true               [grounded — the time bin]
  where/how        none/none          [ABSENT (none) — honestly unknown]
  w_record.score   0.60               [MECHANICAL — fraction of W's TRUE]
HOW SURE / HOW SOUND (the epistemics):
  guarantee.tier   well_formed        [EARNED — capped at the unattested floor]
  calibration      conformal FAR≤0.001[ATTACHED — distribution-free bound]
  cross_check      true               [MECHANICAL — distinct⟷entropy agree]
  custody          none               [ABSENT (none) — unsigned CSV, honest]
  validity         none               [unchecked — no payload schema]
  trustworthiness  none               [DERIVED — kjoin(custody, validity)]
WHERE IT CAME FROM (the justification):
  provenance CID   ea60f133c555559b…  [content-addressed root]
  SHACL conforms   True               [MECHANICAL — self-falsifying shapes]
```

## What this demonstrates

A single alert — "IP 10.3.27.24 password-sprayed 20 accounts" — and *attached to it*, machine-readable and
walkable from one content-addressed CID, is the entire reason to believe it. In a traditional SIEM this is
scattered (the rule in one place, the author in git, the data lineage in a pipeline config) and the
epistemic parts are **written down nowhere**. Here they travel with the result. Reading the claims by class:

- **Mechanically checked** (the substrate computed and could falsify them): the `decision` (`kjoin` of the
  ∃-detect and the temporal ∀-validate), the `score` (conformal p-value), the `cross_check` (an
  *independent* measure — distinct-count — agreed with the entropy detector; had they disagreed this would
  read `both`, a soundness alarm), and **`SHACL conforms = True`** (the provenance graph passes the
  self-falsifying well-formedness shapes — the `well_formed` tier is *earned*, not asserted).
- **Honestly absent** (`none`, never faked to `false`): `custody`, `trustworthiness`, `where`/`how`. The
  corpus is an **unsigned CSV** — not attested evidence — so the substrate reports custody `none` and
  refuses to manufacture trust. This is the `None`-vs-`False` discipline visible in the output: "we didn't
  verify the chain" is *not* "the chain is bad."
- **Earned**: the `guarantee.tier` is `well_formed` — capped at the floor *because* the ingest path is an
  unattested decode (a `bounded` tier would require a verified ingest); the cap is computed, not chosen.
- **Attached**: the `calibration` says `FAR ≤ 0.001, conformal` — the false-alarm honesty carried on the
  verdict, not buried in a tier.
- **Asserted / derived / grounded**: `technique` is the human ATT&CK label; `trustworthiness` is the
  *derived view* `kjoin(custody, validity)`; the W's are grounded telemetry facts (and the `w_record.score`
  of 0.60 honestly reflects that only 3 of 5 W's are confirmed — an unattributed-where/how detection scores
  itself *down*, not falsely up).

## Why it's the proof

This is the thesis made concrete: **no result is asserted that isn't justified back to its inputs and shown
on demand**, and every honesty discipline canon exists for is *visible in one verdict* — the contradiction
carrier (`cross_check`/`decision` → `both`), the absence carrier (`none`, not `false`), the earned-not-
claimed tier, the self-falsifying SHACL, the attached calibration. The "high-quality output on real data"
goal, in one object: an alert you can act on *because* the receipts are attached and honest. Remaining
holes are coverage (more detectors emitting this same fully-justified shape) and the optional
machine-checked numeric proof — not the verdict's completeness on this detection.
