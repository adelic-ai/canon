# canon/contracts — the narrow-waist base

**Status:** DRAFT scaffold, 2026-05-30. Rationale and full architecture:
`../design/self_validation_architecture.md` (read it first).

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

## Status discipline

Every file states its own status. These are DRAFTS — the home and the shape are
established; the precise encodings (param canonicalization, hash default, predicate
schemas) are open and flagged inline. Borrowed standards (PROV-O, in-toto/DSSE, SHACL,
Verifiable Credentials) are *referenced, not redefined* here.
