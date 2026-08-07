# Start here

canon is large and most of it won't be what you came for. This is a router, not a summary — it names
the shortest path to each thing canon actually claims, and says what to skip.

If you haven't yet, [`README.md`](README.md) has the one-paragraph thesis and an honest status section.
Read that first; it's short.

---

## Path 1 — the core idea (start here if you read nothing else)

Three documents, in order. Roughly an hour.

1. **[`design/through_line.md`](design/through_line.md)** — orientation, not spec. Why the repo is
   shaped the way it is, what was tried and dropped, and the framing everything now serves.
2. **[`design/warrant_is_relational.md`](design/warrant_is_relational.md)** — the sharpest statement of
   the central claim: the *derivation*, not the result, is what carries trust. It was recovered from a
   thread running RDF/OWL → reasoners → entailment → *"is an ATT&CK technique a lemma or a hypothesis?"*,
   which is the question the rest of the repo exists to answer.
3. **[`design/justified_verdict_substrate.md`](design/justified_verdict_substrate.md)** — the same claim
   made concrete: justification as a **fold of the same content-addressed object as the result**, so it
   travels with the result instead of being a log written beside it.

The full architecture behind these is
[`design/self_validation_architecture.md`](design/self_validation_architecture.md) — the spine both
realization versions answer to. Longer; read it when the three above have landed.

## Path 2 — how the claim is mechanically enforced

If you want to know whether any of that is real rather than asserted:

- **[`contracts/README.md`](contracts/README.md)** — why contracts come first, and why this directory is
  deliberately *not* a Python package.
- **[`contracts/fold_protocol.md`](contracts/fold_protocol.md)** — what a fold is: a `≤_k`-monotone map
  from a node into the carrier, plus the locality / monotonicity / totality requirements.
- **[`contracts/carrier.md`](contracts/carrier.md)** — the Belnap four-valued bilattice every fold
  computes in, and the universal `≤_k`-monotonicity invariant. This invariant is the acceptance test:
  "add concern N without touching concern M" is exactly monotonicity, and it is CI-checkable.
- **[`contracts/guarantee_certificate.schema.json`](contracts/guarantee_certificate.schema.json)** — the
  per-node tier (machine-checked / bounded / well-formed / **absent**), per-result demotion, and
  *recorded absence*. Absence being a first-class value is the point.
- **[`contracts/custody.md`](contracts/custody.md)** — chain of custody at the ingest boundary, and the
  one-hash-three-roles seam.

## Path 3 — formal semantics and ontology

If you work on threat-model automation, ATT&CK/D3FEND mapping, or ontology-backed security tooling,
this is the part of canon adjacent to your problem:

- **[`packages/semantic-core`](packages/semantic-core)** — typed wrappers over rdflib (graph + SPARQL),
  owlready2 (OWL DL reasoning), and pySHACL (validation), plus FCA implication-basis extraction to a
  concept lattice. Protocols at the boundaries so nothing downstream binds to a vendor API.
- **[`packages/semantic-cyber`](packages/semantic-cyber)** — D3FEND adopted as the defensive knowledge
  graph *as OWL*, not flattened into an exchange format. Includes local counter-derivation that
  replicates the d3fend.mitre.org API's defensive-counters-offensive logic via SPARQL over OWL
  restrictions, so there's no API runtime dependency.
- **[`design/substrate_justification.md`](design/substrate_justification.md)** — the epistemic defense of
  *how* canon uses Belnap / SKOS / FCA and why the composition is legitimate. This is the internal
  reviewable argument; if you want to attack the foundations, attack here.

Corpora are fetched, never vendored:
`uv run --package semantic-cyber python scripts/fetch_d3fend.py`.

## Path 4 — cross-corpus detection knowledge

**[`packages/omega`](packages/omega)** — where the major rule libraries (Sigma, MITRE CAR) overlap,
diverge, and are silent, resolved onto ATT&CK as a common spine, with graded relations expressed as SKOS
rather than asserted. Includes ATLAS coverage cartography — and note that its headline finding is a
*silence*: ~80% of ATLAS techniques come back unreachable by any ATT&CK-speaking corpus.

Two caveats: this is a **synced copy**; the live repo is
[github.com/adelic-ai/omega](https://github.com/adelic-ai/omega). And nothing in canon imports it — it's
a co-located workspace member, not a component.

---

## What to skip, and why it's here

- **`packages/detection`** (~19k lines, over half the repo) — telemetry semantics above `forge-core`:
  real events → candidate streams → the canonical `DetectionVerdict`. Skip it unless detection
  engineering is your field. It matters for one reason: it is the load-bearing exercise that stress-tested
  the substrate against real data rather than a toy, and `design/fold_grounding_lsass_real.md` plus
  `range/kerberos-ticket-hash` are the places a claim got checked against a real capture instead of
  a reviewer's judgment.
- **`packages/forge-core`** — the domain-agnostic statistical spine (features, tests, FP control). No
  domain assumptions; cyber is a consumer, not an owner.
- **`packages/kdc`**, **`packages/synthcyber`**, **`range/`** — ground-truth generators and capture
  ranges. Instruments, not thesis.
- **`rust/`**, **`web/`** — a hot-path emitter spike and visualization surfaces.

## Honest state

The [`README.md`](README.md) status section is the accounting. The short version: 999 tests pass, the
contracts are pinned and mechanically enforced **for the one Python binding** — so the polyglot claim is
not validated — and the repo is visibly shaped by its first serious use case.

canon is a research and learning artifact, not an adoption play. It has to stand as an object of thought
*and* actually work; working is necessary, not sufficient.
