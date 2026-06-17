# canon/contracts — the narrow-waist base

**Status:** PINNED + ENFORCED for the Python binding (audited 2026-06-17; the old "DRAFT scaffold,
2026-05-30" label predated every pin and was stale). The core contracts are stable in shape AND
mechanically enforced — see *Enforcement* below. What is **not** yet validated is the *polyglot* claim:
there is exactly one binding (Python), so the contracts are "Python's interface, enforced" — not yet
*proven* language-independent. Rationale and full architecture: `../design/self_validation_architecture.md`.

This directory is **the base everything else falls out of** — the language-independent
*source of truth* for the contracts every joint mates through. It is deliberately **not**
under `packages/`: if it were a Python package it would be Python-owned, and then Rust,
OCaml, and Coq could not treat it as the shared source of truth. Each language gets a
*thin binding* that reads these artifacts; none owns them.

This is canon's **narrow waist** (the IP-hourglass / WASM / LSP pattern): one stable
interchange at the center — CID-addressed nodes plus a handful of standard artifact
formats — and every implementation (`packages/` Python, future `rust/`, future `proofs/`)
varies independently above and below it.

## Why contracts first

A wrong implementation is cheap to redo; a wrong contract is expensive (everything bolted
to it moves). Pluggability and the swap-seams *fall out* of the contracts. The fold
*internals* (confidence math, temporal recognizer, Belnap algebra) are real work the
contract only bounds the shape of. So: cut the contracts first, then the skeleton and the
seams are free and the muscle is built behind them.

## The contracts

- `cid.md` — **CID** (Content IDentifier): how a node's content-address is computed.
  The one primitive that is identity, provenance, custody, swap-seam, and recursion point
  at once.
- `carrier.md` — the **Belnap four-valued bilattice** every fold computes in, and the
  universal `≤_k`-monotonicity invariant.
- `fold_protocol.md` — what a **fold/interpreter** is (a `≤_k`-monotone map from a node
  into the carrier), the locality + monotonicity + totality requirements, and the
  core-vs-periphery split.
- `guarantee_certificate.schema.json` — the per-node **GuaranteeCertificate**: tier
  (machine-checked / bounded / well-formed / absent), per-result demotion, recorded
  absence.
- `custody.md` — **chain of custody** at the ingest boundary: in-toto/DSSE (borrowed) and
  the one-hash-three-roles seam (ingest Entity CID = in-toto product digest = root
  `prov:Entity`).
- `shapes/` — SHACL shapes (well-formedness contracts), as they are authored.
- `detection_verdict.schema.json` — **the canonical detection-battery standard**: the unit
  every detector emits, tying the five folds (decision/confidence/W-grounding/guarantee/
  custody) to one content-addressed provenance node. The standard is the *schema*, not a
  fixed list of detectors.
- `fidelity_attestation.schema.json` — the justified-verdict substrate applied to **a rule
  itself** instead of an event: a content-addressed, reproducible claim about what a
  specific detection rule *covers* and *structurally cannot*, grounded on a named corpus.
  The canon-novel artifact of the detection inversion (Sigma/CAR carry only free-text
  false-positive notes; this is machine-checkable). A required `scope` field forces the
  claim to stay *"rule R, on corpus C, w.r.t. technique T"* — never universal — and a
  non-trivial verdict must carry a structured `cause` + reproducible `evidence`, so it
  cannot degrade to opinion-with-a-hash.

## Enforcement (the audit, 2026-06-17)

The honest finding: **nothing here is aspirational prose** — every core contract is enforced, by the
mechanism that fits its kind. Three modes:

- **Schema-validated** — code validates instances against the JSON Schema.
  `detection_verdict.schema.json` is the strongest: the emitter's output is checked against it in
  `test_verdict.py`, `test_fanout.py`, `test_offhours.py`, `test_coordination.py` — the verdict cannot
  drift from the standard without a test failing.
- **SHACL-validated** — the shapes run *in the emit path*, and the guarantee tier follows conformance.
  `shapes/detection.shapes.ttl` (every op-plan records its params) + `shapes/cross_model.shapes.ttl`
  (corroboration backed by a witness). Enforced live, not just in tests. (`detection/_verdict.py`.)
- **Property-test-enforced** — the prose (`.md`) contracts are *not* schema-validatable (you cannot
  JSON-Schema "every fold is `≤_k`-monotone"), so they are pinned by exhaustive / property tests — which
  *are* enforcement, the PROVEN-tier kind: `carrier.md` ⇐ Belnap algebra exhaustive over the 4-value
  domain (`test_carrier.py`); `fold_protocol.md` ⇐ the monotonicity acceptance test (`test_monotone.py`);
  `cid.md` ⇐ one-hash-three-roles (`test_custody.py`); `custody.md` ⇐ the custody-fold tests.
- **Referenced / peripheral** — `guarantee_certificate.schema.json` (read by `guarantee.py`/`tier.py`);
  `fidelity_attestation.schema.json` (experiments only — the rule-attestation artifact, not yet in proper);
  `regime_record.schema.json` (the regime-ledger sidecar, one test).

So the contracts are real and pinned. The genuine open frontier is **not** "finish the contracts" — it is
that all enforcement is of the *Python* binding. A contract with one consumer is its interface hoisted
upward; the narrow-waist *claim* (multiple implementations, one contract, inherit each other's proofs) is
only **proven** by a second binding (a thin Rust/OCaml reader, or — dovetailing with the `machine_checked`
tier — an F\*/Coq spec that is simultaneously a second consumer AND the proof path). Borrowed standards
(PROV-O, in-toto/DSSE, SHACL, Verifiable Credentials) are *referenced, not redefined* here.
