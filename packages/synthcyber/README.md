# synthcyber

A standalone generator of **synthetic, correct-by-construction labeled cyber datasets**. canon is *one
consumer*, not the owner — `synthcyber` depends on nothing from canon (the engine/workspace boundary:
data-production lives outside the detection engine).

- **`scenarios`** — labeled attack instances spanning variants × telemetry channels (the fidelity dataset):
  every malicious event is placed by the generator, so its label is known by construction.
- **`adversarial`** — `(rule, event, expected)` cases that stress a detector's string-semantics (the
  emitter-conformance dataset).
- **`recipe`** — `recipe_cid` content-addresses a scenario set (reproducible, citable corpora) and `compose`
  merges them.

Consumers (run detectors over this data) live in canon: `detection.scenarios.variant_coverage`,
`detection.adversarial.attest_corpus`, `detection.fidelity_scorecard`. The dependency points **canon →
synthcyber**, never the reverse.

**Honest scope.** Synthetic events validate detection *mechanism/logic* against representative artifacts, not
field-realism — realism is a recorded claim, not a guarantee results transfer to the wild. Not yet built (layer
2+, see `canon/design/dataset_generator_product.md`): difficulty/realism knobs, OCSF serializer, a git-backed
catalog, a bounded LLM-proposer, a CLI.
