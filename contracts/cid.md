# Contract: CID — node content-address

**Status:** DRAFT, 2026-05-30. The foundational contract; everything addresses through it.

A **CID (Content IDentifier**, from IPLD/IPFS) is a *self-describing* content address:

```
CID = [version][multicodec][multihash]
multihash = [hash-function-code][digest-length][digest-bytes]
```

Self-describing is the point: the CID carries *which* hash function produced it, so the
algorithm is migratable (when a hash weakens) without breaking the addressing scheme.
**Do not hardcode `sha256`** — emit a CID.

## How a node's CID is computed

A node is either a **source** (raw input, no producer) or **derived** (produced by an
Activity).

- **Derived node:** the CID is the multihash over the *canonical serialization* of
  `(op_name, params, [parent CIDs in argument order])`. Identical sub-DAGs therefore share
  a CID → free dedup/memoization. This is the Merkle-DAG property; it is not novel and is
  inherited, not invented.
- **Source node:** identity is by *reference*, not by hashing a (possibly huge) payload —
  a stable `name`/`source_id` if given, else a digest of the payload when the payload is
  the evidence itself (an ingested log — see `custody.md`, where the source CID *equals*
  the in-toto product digest). The contract: **never hash large arrays for identity;** a
  named source is content-addressed by its name, an evidence source by its byte digest.

## Canonical serialization (OPEN — must be pinned)

The CID is only stable if the serialization is canonical across languages. Decisions to
make before this contract is final:

- **Param encoding.** Params must serialize deterministically and identically in Python,
  Rust, OCaml. Candidates: JSON Canonicalization Scheme (RFC 8785), or **DAG-CBOR**
  (IPLD's canonical CBOR — preferred, since it is the native IPLD serialization and pairs
  with CIDs). Floats and large arrays need an explicit rule (arrays are *inputs/sources*,
  not params — see `custody.md`/`carrier.md`; params are scalars).
- **Default multihash.** Likely `sha2-256`, recorded in the CID so it can change.
- **op_name namespacing.** Op names must be globally unambiguous (package-qualified) so a
  CID can't collide across domains.

## One hash, three roles (the keystone)

A node's CID is simultaneously its **Merkle id** (dedup/structural sharing), its
**`prov:Entity` identity** (computation provenance), and — at the ingest boundary — its
**in-toto subject/product digest** (custody). It is *also* the **swap-seam** (any language
hashing the same canonical bytes sees the same node) and the **recursion point** (a node
is one CID outside, a sub-DAG of CIDs inside). Five jobs, one primitive. Getting the
canonical serialization right is therefore load-bearing for the entire substrate.
