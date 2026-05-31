"""The custody fold — were the bytes tampered between entry and evaluation?

Contract: ``~/canon/contracts/custody.md`` + architecture spine §6. Custody answers a
*different* question from provenance: provenance is "how was it computed" (the PROV fold
inside the computation); custody is "were the ingested bytes tampered between the log's
point of entry and evaluation". The two meet at the keystone source node.

This is a carrier-valued (Belnap :class:`~provenance.carrier.Four`) fold:

* a source's custody is its **leaf verdict** from an ingest attestation —
  signed + live + digest-matched → ``TRUE``; digest mismatch → ``FALSE`` (tampered);
  absent / unsigned / silent feed → ``NONE`` (NOT ``TRUE`` — "no data is not
  data-says-fine"; the cid.md PIN 4 rule that a bare reference carries no integrity, and
  the §6 feed-liveness rule).
* a derived node has **no independent custody** (in-toto stays at the boundary; internals
  are PROV, not custody). Its custody is the composition of its inputs' custody by
  :func:`~provenance.carrier.tmeet` (truth-meet): the chain is sound (``TRUE``) only if
  every link is sound; any tampered link (``FALSE``) taints the whole (FALSE is
  absorbing); otherwise unknown (``NONE``). ``tmeet`` is ``≤_k``-monotone, so the fold
  satisfies the universal invariant.

**Feed-liveness is custody** (§6): a silent feed yields ``NONE``, which is exactly the
signal the temporal fold needs so "C never occurred in W" is ``True`` only on a *live*
feed, never on a silent one. The guarantee fold already consumes this verdict as its
runtime monitor.

Keystone scope (honest): custody.md's keystone is "the evidence source's CID = the
in-toto product digest = the root prov:Entity id". Today :class:`~provenance.entity.Entity`
hashes ``("src", name)`` for a source, not its payload, so this fold verifies digest-match
against an independently computed :func:`evidence_digest`. Wiring an evidence source's
``Entity.id`` to *be* its payload digest (fully realizing the one-hash-three-roles seam) is
a deferred ``entity.py`` change — flagged here, not faked.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from provenance.carrier import FALSE, NONE, TRUE, Four, tmeet
from provenance.entity import Entity
from provenance.interpret import lineage


@dataclass(frozen=True, slots=True)
class CustodyAttestation:
    """The minimal projection of an in-toto/DSSE custody record the fold reads.

    canon does **not** re-mint the in-toto/DSSE format (custody.md: borrowed, not
    redefined); this is just the fields the leaf verdict needs. ``product_digest`` is the
    sha2-256 hex the signed statement vouches for — the keystone digest that must equal the
    evidence's actual content digest.
    """

    product_digest: str
    signed: bool = True
    feed_live: bool = True


def evidence_digest(payload: bytes | str) -> str:
    """The sha2-256 hex of evidence bytes — an evidence source's content digest.

    This is the digest that, under the keystone, *is* the source CID and the in-toto
    product digest (cid.md: an evidence source is content-addressed by its byte digest).
    Only byte/str evidence is in scope — arrays are inputs, not evidence, and are never
    hashed for identity (cid.md).
    """
    if isinstance(payload, str):
        b = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        b = bytes(payload)
    else:
        raise TypeError(
            f"evidence_digest needs bytes/str evidence, got {type(payload).__name__}"
        )
    return hashlib.sha256(b).hexdigest()


def _source_custody(source: Entity, att: CustodyAttestation | None) -> Four:
    """Leaf verdict for a source from its attestation. Belnap-honest absences are ``NONE``."""
    if att is None:
        return NONE  # no signer / not evidence — unknown, never True
    if not att.feed_live:
        return NONE  # silent feed — the §6 temporal-negation signal
    if not att.signed:
        return NONE  # unsigned claim carries no integrity (cid.md PIN 4)
    # The keystone check: the evidence's actual content digest must match the vouched one.
    if evidence_digest(source.payload) == att.product_digest:
        return TRUE  # intact, signed, digest-matched chain
    return FALSE  # digest mismatch — tampered between entry and evaluation


def custody(
    root: Entity,
    *,
    attestations: dict[str, CustodyAttestation] | None = None,
) -> dict[str, Four]:
    """Fold the DAG to a custody :class:`~provenance.carrier.Four` per node, keyed by id.

    ``attestations`` maps a *source* node id to its ingest attestation; a source without
    one earns ``NONE``. A derived node's custody is :func:`~provenance.carrier.tmeet` over
    its inputs' custody (a no-input derived node is the vacuous ``TRUE`` — the tmeet
    identity: nothing was ingested, so nothing could be tampered). The root's verdict is
    ``result[root.id]``.
    """
    attestations = attestations or {}
    verdicts: dict[str, Four] = {}
    for node in lineage(root):  # dependency order: every child precedes its parent
        nid = node.id
        if node.producer is None:
            verdicts[nid] = _source_custody(node, attestations.get(nid))
        else:
            v = TRUE  # tmeet identity; vacuous custody for a derived node with no inputs
            for child in node.producer.used:
                v = tmeet(v, verdicts[child.id])
            verdicts[nid] = v
    return verdicts
