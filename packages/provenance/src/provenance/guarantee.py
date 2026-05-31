"""The guarantee fold — the tier a result *earned*, computed per node over the DAG.

Contract: ``guarantee_certificate.schema.json`` + architecture spine §4. This realizes
"a tier is earned, never asserted" as a genuine fold: ``guarantee(node)`` depends only on
the node and its children's certificates (``fold_protocol.md`` locality), and it is total
(a certificate for *every* node, ``ABSENT`` where nothing was claimed).

Two honesty mechanisms from §4, both computed (not asserted):

1. **Weakest link.** A node's earned tier is the :func:`~provenance.tier.tier_meet` of its
   own (post-monitor) capability with every child's earned tier. A machine-checked op fed a
   merely well-formed input can only honestly earn well-formed downstream.
2. **Per-result demotion, tied to the carrier.** An assumption-bearing tier
   (``BOUNDED``/``MACHINE_CHECKED``) only *stands* if its runtime-monitor verdict is Belnap
   :data:`~provenance.carrier.TRUE` (the precondition was confirmed to hold on *this*
   input). A verdict of ``NONE`` (no monitor ran — "no data ≠ data-says-fine"), ``FALSE``
   (violated), or ``BOTH`` (conflicting monitors — a soundness alarm) caps the tier at the
   :data:`~provenance.tier.FLOOR` and records the demotion.

A missing claim is a **recorded absence** (``tier=ABSENT``, ``absence=("guarantee_claim",)``),
never a silent blank.

Scope note: the tier axis is orthogonal to the Belnap knowledge axis (``carrier.py``), so
this fold is monotone in the *tier* order, not ``leq_k``. Wiring ``BOTH`` to a separate
per-node Belnap soundness-alarm status is a later fold; here a ``BOTH`` verdict only
demotes (and is recorded as the reason), it does not yet propagate as an alarm value.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from provenance.carrier import BOTH, FALSE, NONE, TRUE, Four
from provenance.entity import Entity
from provenance.interpret import lineage
from provenance.tier import ASSUMPTION_BEARING, FLOOR, Tier, tier_meet


@dataclass(frozen=True, slots=True)
class Demotion:
    """Why an assumption-bearing tier did not stand on this input."""

    from_tier: Tier
    reason: str


@dataclass(frozen=True, slots=True)
class GuaranteeCertificate:
    """The guarantee fold's per-node output. ``subject_cid`` is the node's content address
    (``Entity.id`` is the recipe-node CID, ``cid.md`` PIN 1)."""

    subject_cid: str
    tier: Tier
    claimed: Tier
    demotion: Demotion | None = None
    absence: tuple[str, ...] = ()


_DEMOTION_REASON = {
    NONE: "assumption monitor absent — no data is not data-says-fine",
    FALSE: "precondition violated on this input",
    BOTH: "conflicting monitor verdicts (Both) — soundness alarm",
}


def _capability(claimed: Tier, verdict: Four) -> tuple[Tier, Demotion | None]:
    """A node's own tier after applying its runtime-monitor verdict (before composition).

    A non-assumption tier stands as-is. An assumption-bearing tier stands only on a
    confirming ``TRUE`` verdict; otherwise it is demoted to the floor and the demotion is
    recorded.
    """
    if claimed not in ASSUMPTION_BEARING:
        return claimed, None
    if verdict is TRUE:
        return claimed, None
    return FLOOR, Demotion(from_tier=claimed, reason=_DEMOTION_REASON[verdict])


def guarantee(
    root: Entity,
    *,
    claims: dict[str, Tier],
    monitors: dict[str, Four] | None = None,
) -> dict[str, GuaranteeCertificate]:
    """Fold the DAG to a :class:`GuaranteeCertificate` per node, keyed by ``Entity.id``.

    ``claims`` maps a node id to the tier its op *can* provide if its assumptions hold;
    a node absent from ``claims`` earns ``ABSENT`` with the absence recorded. ``monitors``
    maps a node id to the Belnap verdict of whether its precondition held on this input
    (default ``NONE`` — unconfirmed). The root's certificate is ``result[root.id]``.
    """
    monitors = monitors or {}
    certs: dict[str, GuaranteeCertificate] = {}
    for node in lineage(root):  # dependency order: every child precedes its parent
        nid = node.id
        has_claim = nid in claims
        claimed = claims.get(nid, Tier.ABSENT)
        verdict = monitors.get(nid, NONE)

        capability, demotion = _capability(claimed, verdict)
        # weakest link: earned = meet of own capability and all children's earned tiers
        earned = capability
        for parent in node.used:
            earned = tier_meet(earned, certs[parent.id].tier)

        certs[nid] = GuaranteeCertificate(
            subject_cid=nid,
            tier=earned,
            claimed=claimed,
            demotion=demotion,
            absence=() if has_claim else ("guarantee_claim",),
        )
    return certs
