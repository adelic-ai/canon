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

from dataclasses import dataclass

from provenance.carrier import FALSE, NONE, TRUE, Four, tmeet
from provenance.entity import Entity, evidence_digest  # evidence_digest: the identity↔digest seam
from provenance.interpret import lineage

__all__ = [
    "CustodyAttestation",
    "custody",
    "evidence_digest",
    "CustodyStep",
    "Localization",
    "localize",
]


@dataclass(frozen=True, slots=True)
class CustodyAttestation:
    """The minimal projection of an in-toto/DSSE custody record the fold reads.

    canon does **not** re-mint the in-toto/DSSE format (custody.md: borrowed, not
    redefined); this is just the fields the leaf verdict needs. ``product_digest`` is the
    sha2-256 hex the signed statement vouches for — the keystone digest that must equal the
    evidence's actual content digest (which, for an evidence source, *is* its CID).
    """

    product_digest: str
    signed: bool = True
    feed_live: bool = True


def _source_custody(source: Entity, att: CustodyAttestation | None) -> Four:
    """Leaf verdict for a source from its attestation. Belnap-honest absences are ``NONE``."""
    if att is None:
        return NONE  # no signer / not evidence — unknown, never True
    if not att.feed_live:
        return NONE  # silent feed — the §6 temporal-negation signal
    if not att.signed:
        return NONE  # unsigned claim carries no integrity (cid.md PIN 4)
    # The keystone check: does the evidence's content digest match the vouched product digest?
    # For an evidence source the digest IS its CID (source.id), so this is literal CID equality
    # — one hash, three roles. For a by-reference source there is no CID commitment to the
    # bytes, so fall back to hashing the payload directly.
    actual = source.id if source.is_evidence else evidence_digest(source.payload)
    if actual == att.product_digest:
        return TRUE  # intact, signed, digest-matched chain
    return FALSE  # digest mismatch — tampered between entry and evaluation


def custody(
    root: Entity,
    *,
    attestations: dict[str, CustodyAttestation] | None = None,
    chains: dict[str, "tuple[CustodyStep, ...]"] | None = None,
) -> dict[str, Four]:
    """Fold the DAG to a custody :class:`~provenance.carrier.Four` per node, keyed by id.

    A source's leaf verdict comes from one of two paths (extend, not replace):

    * ``chains`` maps a source node id to a multi-hop :class:`CustodyStep` chain — the richer,
      contract-aligned path; its leaf verdict is :func:`localize`\\ ``(chain, held).verdict``
      (the structured :class:`Localization` is recovered by calling ``localize`` directly).
    * ``attestations`` maps a source node id to a single ingest attestation — the degenerate
      one-hop path.

    A chain takes precedence where both are given; a source in neither earns ``NONE``. A
    derived node's custody is :func:`~provenance.carrier.tmeet` over its inputs' custody (a
    no-input derived node is the vacuous ``TRUE``). The root's verdict is ``result[root.id]``.
    """
    attestations = attestations or {}
    chains = chains or {}
    verdicts: dict[str, Four] = {}
    for node in lineage(root):  # dependency order: every child precedes its parent
        nid = node.id
        if node.producer is None:
            chain = chains.get(nid)
            if chain is not None:
                # held bytes = the source's content digest (its CID, for an evidence source —
                # the keystone alignment, so the chain's last product must equal it).
                held = node.id if node.is_evidence else evidence_digest(node.payload)
                verdicts[nid] = localize(chain, held).verdict
            else:
                verdicts[nid] = _source_custody(node, attestations.get(nid))
        else:
            v = TRUE  # tmeet identity; vacuous custody for a derived node with no inputs
            for child in node.producer.used:
                v = tmeet(v, verdicts[child.id])
            verdicts[nid] = v
    return verdicts


# ── multi-hop custody chain + localization ───────────────────────────────────────────────
#
# The single :class:`CustodyAttestation` above answers a binary "did the held bytes match the
# one vouched digest". But custody.md's pinned shape is a *chain* — each ingest/normalize/
# transform hop is its own in-toto step (`materials` → `product`), and custody is
# reconstructed by **digest-matching** across hops (a downstream material = an upstream
# product), not explicit pointers. A digest-consistent chain does more than say "intact": it
# lets you *localize*. Walking it backward from the bytes canon holds **exonerates** the
# pure-relay hops (a relay that corrupted-then-signed is visible — either product != material
# on a declared pass-through, or a seam mismatch with its neighbour), leaving the suspect set
# = {origin} ∪ {declared-transform hops}: the only places content can be introduced without a
# detectable anomaly (the origin is pre-attestation; a transform legitimately changes content,
# so corruption hides inside it). This is the actionable half of a trustworthiness ``Both``
# (architecture spine §6 + the validity fold): "contested chain — start at the last hop, walk
# back, scrutinize these." Assumes each hop signs with its own key and cannot forge another's.


@dataclass(frozen=True, slots=True)
class CustodyStep:
    """One in-toto step in the chain: ``materials`` (input digests) → ``product`` (output
    digest), signed by ``agent``.

    ``transform=False`` is a declared **pass-through**: ``product`` must equal its single
    material, so any change is a visible anomaly. ``transform=True`` legitimately changes
    content (``product != materials`` is expected) — which is exactly where corruption can
    hide under cover of a sanctioned transform, so a transform hop can never be exonerated by
    digest alone."""

    agent: str
    materials: tuple[str, ...]
    product: str
    signed: bool = True
    transform: bool = False


@dataclass(frozen=True, slots=True)
class Localization:
    """The result of walking a custody chain backward from the held bytes.

    ``verdict`` is the chain-integrity Belnap value (``TRUE`` consistent+signed+anchored;
    ``FALSE`` a proven in-transit tamper, localized at ``seam_break``; ``NONE`` unsigned/
    unverifiable). ``exonerated`` are the pure-relay agents proven clean; ``suspect`` is where
    content could have been introduced — ``{origin} ∪ {transform hops}`` plus any anomalous
    hop. ``suspect`` is populated even when ``verdict`` is ``TRUE`` (the validity-``Both`` case:
    the chain relayed faithfully, but *something* upstream emitted the bunk)."""

    verdict: Four
    exonerated: tuple[str, ...]
    suspect: tuple[str, ...]
    seam_break: str | None = None


def localize(chain: tuple[CustodyStep, ...], held_digest: str) -> Localization:
    """Walk ``chain`` (ordered origin → … → ingest) backward from ``held_digest``.

    The anchor is the bytes canon actually holds: the last step's ``product`` must equal
    ``held_digest``. Then each step's ``materials`` must contain the previous step's
    ``product`` (the digest-matched seam); a declared pass-through must preserve its material.
    A break in either is a proven in-transit tamper (``FALSE``), localized at that hop. With no
    break, the chain is ``TRUE`` if every step is signed, else ``NONE`` (unverifiable). The
    suspect set is ``{origin} ∪ {transform hops}`` regardless — the residue digest-custody
    cannot clear."""
    if not chain:
        return Localization(NONE, (), (), seam_break=None)

    # The first hop is the origin: it emits the initial content (pre-attestation), so it is
    # permanently suspect and never relay-evaluated — digest-custody can never vouch for what
    # predates the chain (that residue is the validity axis' job, not custody's).
    suspect: list[str] = [chain[0].agent]
    exonerated: list[str] = []
    seam_break: str | None = None

    # Anchor: the held bytes must be the last step's product.
    if chain[-1].product != held_digest:
        seam_break = f"evaluation: held bytes do not match {chain[-1].agent}'s product"

    for i in range(1, len(chain)):
        step, prev = chain[i], chain[i - 1]
        if step.transform:
            if step.agent not in suspect:
                suspect.append(step.agent)  # legitimate transform — corruption can hide here
        else:
            # Declared pass-through: product must equal its single material, or it altered
            # content it should have relayed — a visible anomaly.
            if len(step.materials) != 1 or step.materials[0] != step.product:
                seam_break = seam_break or f"{step.agent}: pass-through altered content"
                if step.agent not in suspect:
                    suspect.append(step.agent)
            elif step.signed:
                exonerated.append(step.agent)  # signed, content-preserving relay — clean
        # Seam to the previous hop: this step must consume the previous product.
        if prev.product not in step.materials:
            seam_break = seam_break or (
                f"{step.agent} does not consume {prev.agent}'s product (seam mismatch)"
            )

    if seam_break is not None:
        verdict = FALSE  # proven in-transit tamper, localized
        exonerated = []  # a broken chain exonerates no one
    elif all(s.signed for s in chain):
        verdict = TRUE
    else:
        verdict = NONE  # an unsigned hop — chain unverifiable, never asserted-clean
        exonerated = []

    return Localization(
        verdict=verdict,
        exonerated=tuple(exonerated),
        suspect=tuple(suspect),
        seam_break=seam_break,
    )
