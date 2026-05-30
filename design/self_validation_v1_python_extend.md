# Version 1 — extend the current Python

**Status:** design, 2026-05-30. A realization of `self_validation_architecture.md`
(read that first — this only assigns material per joint and sequences the build).
The prototypy, fast, continuous path: grow the existing `provenance` DAG outward to
custody + justification + the folds, staying in Python, honest about where Python caps
out.

**One-line verdict:** Python reaches the **bounded** and **well-formed** guarantee tiers
in full — which is canon's *actual* detection guarantee (distribution-free Pfa control
is native Python). It cannot reach the **machine-checked** tier on the numpy hot kernel.
So V1 is a complete self-validating substrate *minus bit-level numeric proofs* — and for
most of the value, that minus doesn't bite.

## Joint-by-joint realization

- **Core DAG** — keep the existing `provenance` Entity/Activity DAG. Two edits: (1)
  rename internally to the canonical vocabulary (Merkle node / constructive trace /
  Applicative task) so the code inherits the literature; (2) abstract the id behind a
  CID-style self-describing wrapper instead of hardcoding `sha256`. Stay Applicative —
  guard the boundary against Monadic (value-dependent parents).
- **value / provenance / well-formedness** — already built (`evaluate`, `to_prov`,
  `validate`). Add RDF 1.2 triple-term edge annotations via `rdflib`'s RDF-star support,
  gated behind the fold so a Basic export path survives.
- **custody** — new `custody` module. Bind the existing `in-toto`/`pydsse` Python
  libraries (don't rewrite signing). At ingest: hash the log at point-of-entry, emit a
  DSSE-signed in-toto Statement whose `product` digest *becomes* the CID of the root
  source Entity (the one-hash-three-roles seam, realized as: `source(payload, name=…)`
  takes the in-toto digest as its content-address). The `validate` fold gains a custody
  check: re-hash and confirm the chain from ingest `product` to evaluation `subject`.
  CASE/UCO terms enter as IRIs in the vocabulary module; VC only if signed
  who-touched-it is in the milestone.
- **guarantee** — new fourth fold `guarantee(entity) → GuaranteeCertificate`, a tagged
  union over the three tiers, pinned to the node by content address.
  - *bounded* (the headline — fully Python): conformal prediction via `MAPIE`/`crepes`
    (or a small split-conformal of our own) for the distribution-free Pfa bound; the
    existing CFAR/NP closed forms as the analytic conditional bound; the calibration
    corpus content-addressed into provenance so the guarantee is reproducible.
  - *well-formed*: the SHACL fold + `Hypothesis` metamorphic tests (scale-equivariance,
    statistic-monotone-in-SNR, threshold monotonicity) + `icontract`/`deal` contracts,
    `CrossHair` on the pure-Python orchestration (not the numpy kernel — it can't see in).
  - *machine-checked*: **out of reach in-Python on the hot kernel.** Be explicit in the
    certificate: this tier is unavailable in V1; the most Python offers is contract-checked
    glue. (`nagini` exists but is academic, doesn't handle numpy — not a dependency.)
- **per-result demotion** — a runtime assumption monitor (pure Python: check CFAR
  reference-window homogeneity, feed-liveness) whose verdict is recorded in provenance and
  selects the tier. Cheap; this is what makes V1 "honest per result" despite lacking the
  machine-checked tier.
- **confidence** — new `confidence` fold: Chair–Varshney LLR fusion in log-odds space over
  the AND/OR DAG (numpy). Use content-addressing to flag shared-evidence sub-DAGs
  (correlation-aware, not independence-assumed). A tractable probabilistic-circuit
  evaluator is a Python implementation (no heavy dep needed for the sum/product fold).
- **temporal** — new `temporal` fold. Don't pull in Flink. Implement a small chronicle /
  CEP-pattern recognizer over event-time-sorted records (relaxed contiguity, windows,
  three-valued negation gated on feed-liveness); `RTAMT` (Python) for STL robustness on the
  real-valued sub-conditions. Temporal state held *beside* the DAG as an annotation stream.
- **partiality** — a `Belnap` carrier type {None,True,False,Both} with the four bilattice
  ops, and a `≤_k`-monotonicity property test every fold must pass in CI. This is a type
  change + an invariant, touching no other fold's logic if they were written monotone.

## What V1 honestly is and isn't

- **Is:** a working, end-to-end self-validating substrate — every result carries lineage,
  custody chain, a distribution-free guarantee with a computed honest tier, and a
  Belnap-valued confidence/temporal account, all as folds of one tamper-evident DAG.
- **Isn't:** bit-level machine-checked numerics. The numpy kernels are trusted (covered by
  metamorphic tests + round-off *estimates*, not certificates). If a detector's bit-tight
  round-off bound has real value, V1 cannot give it — that's the V2 frontier.

## Sequencing (each step green, each a fold added without touching the others)

1. CID-ize node identity + canonical-vocabulary rename (no behavior change).
2. `Belnap` carrier + `≤_k`-monotonicity CI gate; lift existing folds to it.
3. `custody` module + the digest-as-CID seam; custody check in `validate`.
4. `guarantee` fold — well-formed tier first (SHACL + Hypothesis + contracts), then
   bounded tier (conformal + analytic), then the runtime monitor + demotion.
5. `confidence` fold (LLR/PC over AND/OR), correlation-aware via shared sub-DAGs.
6. `temporal` fold (chronicle + RTAMT), three-valued negation gated on feed-liveness.
7. Per-detector: assign and record the honest tier; wire `Both` to self-falsification.

## Risk specific to V1

The temptation to let "well-tested numpy" stand in for the machine-checked tier and quietly
drop the distinction. Don't — the certificate must say *machine-checked: unavailable
(Python kernel)*, not imply a guarantee it doesn't have. That honesty is the point; V2
exists precisely to close it where it matters.
