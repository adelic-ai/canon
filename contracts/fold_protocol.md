# Contract: the fold protocol

**Status:** DRAFT, 2026-05-30. What every interpreter over the DAG must be.

A **fold** (interpreter) is a `≤_k`-monotone map from a DAG node — given the node and its
children's *already-folded* results — into a carrier-valued result:

```
fold(node, child_results: [CarrierValue]) -> CarrierValue
```

Evaluating a fold is a topological walk: fold the leaves, then each node from its children.
"The value is one fold among many"; provenance, custody, validation, guarantee, confidence,
and temporal matching are *other folds of the same authoritative structure*, so the
justification of a result **is the same object** as the result.

## The three requirements (all CI-checkable)

1. **Locality** — a fold reads *only* the node and its children's results, nothing else.
   Locality is what makes folds *independent* (the "add N without touching M" property):
   two folds over the same DAG cannot interfere because neither reads the other's state.
2. **`≤_k`-monotonicity** — see `carrier.md`. The acceptance test, as a property test
   feeding `None`/`Both`.
3. **Totality** — a fold handles *every* node variant (exhaustive match). A typed host
   (Rust `enum`/`match`, an ML ADT, a dependently-typed total function) checks this at
   compile time — *interpreter-completeness*; an untyped host (Python) checks it by test.

## The fold family (see the architecture spine §3 for detail)

`value` (evaluate) · `lineage` · `provenance` (→ PROV-O) · `well-formed` (→ SHACL) ·
`guarantee` (→ GuaranteeCertificate) · `confidence` (Chair–Varshney LLR / probabilistic
circuit) · `temporal` (CEP/chronicle + STL) · `custody` (→ in-toto/DSSE at the boundary) ·
`cost` (future).

## Core vs periphery (see architecture spine §2)

The split is drawn by: *does the fold walk the live DAG node-by-node with the carrier, or
consume-a-node-and-emit-a-standalone-artifact?*

- **Core** (one host language, in-process): `value`, `confidence`, `temporal`,
  `partiality`-lifting, `lineage`. Tight inner-loop folds — serializing per node is
  prohibitive.
- **Periphery** (any language, swappable plug-ins, mate by CID + standard artifact):
  `custody` signing, machine-checked numeric proof, `provenance` (PROV-O) export, SHACL
  validation, conformal calibration.

The seam is recursive: a periphery component is itself a node outside and may be a sub-DAG
of further swappable folds inside, with a **black-box vs transparent** knob (justification
stops at a black-box boundary; transparency costs serialization but lets the
provenance/guarantee folds reach inside).

## Per-language binding (thin; reads this spec, does not own it)

- **Python** — `typing.Protocol` for the fold signature; monotonicity + totality by
  `Hypothesis` property tests. This is the *reference* binding (the oracle other languages
  diff against by comparing CID-addressed outputs).
- **Rust** — a `trait`; `enum` + exhaustive `match` gives totality at compile time.
- **ML / dependently-typed** — an ADT + total function; monotonicity encodable in the type
  in a dependently-typed host (proven, not tested).

## OPEN

- Exact `CarrierValue` serialization for the cross-language wire (pairs with `cid.md`'s
  DAG-CBOR decision).
- Whether `child_results` are passed by value or by CID-reference at periphery seams
  (the clean-but-not-free boundary).
