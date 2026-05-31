# Contract: CID — node content-address

**Status:** PINNED, 2026-05-31 (was DRAFT 2026-05-30). The foundational contract;
everything addresses through it. The four pins below are load-bearing for the whole
substrate — see *One hash, three roles*.

A **CID (Content IDentifier**, from IPLD/IPFS) is a *self-describing* content address:

```
CID = [version][multicodec][multihash]
multihash = [hash-function-code][digest-length][digest-bytes]
```

Self-describing is the point: the CID carries *which* hash function produced it, so the
algorithm is migratable (when a hash weakens) without breaking the addressing scheme.
**Do not hardcode `sha256`** — emit a CID.

## What a CID identifies — recipe-node identity (PIN 1)

A canon CID identifies a **recipe-node** — *not* raw output bytes, and *not* semantic
meaning. The hashed object is:

```
recipe_node = { op_name, params, parent_cids, source_identity? }
CID = multihash(canonical_serialization(recipe_node))
```

Three identity schemes were possible; canon picked the middle one deliberately:

1. **output-byte identity** (hash the value) — *rejected*: the value isn't known until
   evaluation, which breaks the lazy DAG.
2. **recipe identity** (hash the recipe) — **chosen.** The CID is available **before
   execution**, exactly what a lazy DAG needs (`Entity.id` is set at `derive()` time
   without firing the kernel — provenance Phases 1/3 depend on this).
3. **semantic identity** (equal iff "mean the same") — *rejected*: hashes must not prove
   meaning. See PIN 3.

Intended consequence: two op-chains that compute the *same value* via different ops/params
get **different CIDs**. Dedup is dedup-of-*computation*, not of result — the structural
firewall that keeps semantics out of identity. (A node's CID is its `prov:Entity` IRI; a
`prov:Entity` is the immutable *output-position of a fixed recipe* — semi-abstract, but
purely syntactic over the recipe. "Recipe-node," not "artifact bytes," is the unit.)

## How a node's CID is computed

A node is either a **source** (raw input, no producer) or **derived** (produced by an
Activity).

- **Derived node:** the CID is the multihash over the *canonical serialization* of
  `(op_name, params, [parent CIDs in argument order])`. Identical sub-DAGs therefore share
  a CID → free dedup/memoization. This is the Merkle-DAG property; it is not novel and is
  inherited, not invented.
- **Source node:** identity is `source_identity`, by one of two routes with **different
  security claims** (see PIN 4): **by-reference** (a stable `name`/`source_id`, to avoid
  hashing a huge payload) or **by-payload-digest** (the byte digest when the payload is the
  evidence itself — an ingested log; see `custody.md`, where the source CID *equals* the
  in-toto product digest). **Never hash large arrays for identity** — array inputs to ops
  are `used`-edges (parent CIDs), not params (Phase 3 already does this for
  `matched_filter`'s template/noise_cov).

## Deterministic canonical encoding (PIN 2)

The CID is stable across languages **iff** the serialization is canonical. Pinned:

- **Encoding: DAG-CBOR** (IPLD's canonical CBOR) — chosen over JCS/RFC 8785 because it is
  the native IPLD serialization, pairs directly with CIDs, and has a single deterministic
  form (sorted map keys, shortest-form integers, no NaN/Inf floats).
- **Default multihash: `sha2-256`**, recorded in the CID so it can be migrated later
  without re-cutting this contract.
- **op_name namespacing:** package-qualified (e.g. `forge_core.detection.ca_cfar`) so a
  CID cannot collide across domains.
- **Numbers:** integer and float are **distinct** encodings (see PIN 3 on `1` vs `1.0`);
  floats use DAG-CBOR's canonical form; NaN/Inf are prohibited in params (lift into the
  carrier instead). Params are scalars — arrays are inputs (`used`-edges), per above.

## Canonicalization must not collapse equivalence (PIN 3)

> **Canonicalization removes serialization noise. It must not collapse semantic
> equivalence.**

It normalizes the *representation* of a logical value; it must never fold two distinct
recipes into one because they would *mean* or *compute* the same thing.

- Allowed (representation noise): stable key order; pinned float/int encoding; deterministic
  list/set encoding.
- Prohibited (equivalence-collapse — smuggles PIN-3's rejected semantic identity into the
  hash): default-filling (`welch(x, nperseg=256)` → `…, window='hann'`); algebraic
  simplification; treating `1` and `1.0` as the same unless the param is contractually
  typed; replacing an op with an equivalent op.

```
same recipe representation  -> same CID
equivalent meaning/result   -> distinct CIDs + an equivalence edge/certificate
```

Semantic equivalence is a **relation between two CIDs**, never an identity merge:
`CID_A --equivalent_by_certificate--> CID_B`. It lives in the layers built for it — the
machine-checked guarantee tier's proven algebraic identities (e.g. *Goertzel recurrence ≡
single-bin DFT*, `../design/self_validation_architecture.md` §4) and RDF/PROV/SKOS/FCA
relations (`skos:exactMatch`, FCA equivalence classes) — **never** in the CID.

## Named-source identity carries no integrity guarantee (PIN 4)

The two source-identity routes are **not the same security claim**:

- **by-payload-digest** — the CID *verifies integrity* (re-hash and compare). Tamper-
  evident; this is the route that powers the one-hash-three-roles seam at ingest.
- **by-reference (name)** — the CID identifies a *trusted handle*, nothing more. You trust
  the name; **no tamper evidence.** The closest thing in the design to "an abstract handle
  wearing a content-address," and the contract states plainly it makes **no** integrity
  claim.

The source-identity route is recorded so a downstream guarantee fold never reads a
by-reference name as tamper-evident — Belnap-honest: a missing integrity claim is `None`,
not `True`.

## One hash, three roles (the keystone)

A node's CID is simultaneously its **Merkle id** (dedup/structural sharing), its
**`prov:Entity` identity** (computation provenance), and — at the ingest boundary, via the
by-payload-digest route — its **in-toto subject/product digest** (custody). It is *also*
the **swap-seam** (any language hashing the same canonical bytes sees the same node) and
the **recursion point** (a node is one CID outside, a sub-DAG of CIDs inside). Five jobs,
one primitive.

This collapse of the heterogeneous provenance surface (Merkle / PROV-O / in-toto — three
id schemes circling one object) into a single key holds **only because of the four pins
above**: recipe-syntactic identity (1), deterministic cross-language encoding (2),
canonicalization that never collapses equivalence (3), explicit per-source tamper-evidence
(4). Get any wrong and the three roles silently desynchronize — the wall the CID dissolves
comes back.
