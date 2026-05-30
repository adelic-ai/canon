# Contract: chain of custody

**Status:** DRAFT, 2026-05-30. The ingest-boundary contract. Borrowed standards are
*referenced, not redefined* here.

Custody answers a different question from provenance: provenance is *how was it computed*
(the PROV fold inside the computation); custody is *were the bytes tampered between the
log's point of entry and evaluation*. They meet at one node (the keystone seam below).

## Borrow (do not rewrite)

- **in-toto Statement + DSSE envelope** — the digest-custody chain. Each ingest / normalize
  / transform hop is an in-toto *step* (`materials` → `products`); custody is reconstructed
  by **digest-matching** (a downstream `subject` digest equals an upstream `product`
  digest), not by explicit pointers. The evaluation is the terminal step whose `subject`
  digest must equal the ingest `product` digest. Keep in-toto at the **boundary** — it
  treats steps as black boxes; do NOT model the internal computation in it (that's PROV).
- **CASE/UCO** `ProvenanceRecord` + custody-action terms — borrowed as **vocabulary only**
  (IRIs), to speak the forensic register (exhibit / acquisition / examiner-or-tool agent /
  custody transfer / hash-at-acquisition). Do NOT adopt the ontology wholesale (it is
  forensics-investigation-shaped, no compute layer).
- **W3C Verifiable Credentials** — for signed *who/what touched it* claims at entry, when
  custody needs more than "which bytes." Independently verifiable signed claims; do not
  hand-roll a signed-claim format.

## The keystone seam — one Entity, three identities

> **The ingested-evidence node's CID = the in-toto `product` digest = the root
> `prov:Entity` identity.**

This single coincidence is the literal join between *chain of custody of the log into the
system* and *justification of the result computed from it*. The evidence source node
(`cid.md`: an evidence source is content-addressed by its byte digest) carries the in-toto
attestation as its custody record and is the provenance root of every derivation downstream.
Walk the provenance DAG back to its root and you arrive at a digest that is *also* the
custody anchor.

## Custody as a Belnap signal — and the feed-liveness tie

Custody is a fold whose value is carrier-valued: intact, signed, digest-matched chain →
`True`; broken/altered → `False`; **no signer / silent feed → `None`** (NOT `True`). This
is load-bearing for the one hard cross-fold seam (architecture spine §6): **temporal
negation under partial data**. "C never occurred within W" is `True` only if the C-feed was
*live*; on a silent feed it must be `None`. **Feed-liveness is custody** — a live,
unbroken feed is intact chain-of-custody — so this custody fold supplies exactly the signal
the temporal fold needs to avoid the absence-of-evidence trap.

## OPEN

- **canon's in-toto `predicateType`** for the ingest attestation (the SLSA-provenance-shaped
  predicate describing where/when/how the log entered). Define the predicate schema.
- Signing key management / trust roots for DSSE and VC issuers.
- Where the ingest tap runs (likely a non-Python boundary process — Go/Rust — emitting the
  DSSE envelope; it is a swappable periphery joint per `fold_protocol.md`).
