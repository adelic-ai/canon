"""DetectionVerdict — the canonical detection unit, assembled from the five folds.

Contract: ``~/canon/contracts/detection_verdict.schema.json`` (PINNED). This is the
**first producer** of that standard — a detector conforms to canon iff it emits a
DetectionVerdict. The verdict is a *sixth interpreter* over the one content-addressed
provenance DAG: it reads the outputs of the five built folds at the detection's **root
node** and projects them into the contract's JSON shape. Justification is not a side-log —
every field traces back to ``provenance`` (the root CID), walkable on demand.

The five folds, at ``root.id``:

* **confidence** (``provenance.confidence``) → the graded ``score`` (probability) *and* the
  Belnap knowledge axis that seeds the detect projection.
* **custody** (``provenance.custody``) → the ingest verdict; ``TRUE`` only when the keystone
  CID-equality holds on a signed, live evidence source.
* **guarantee** (``provenance.guarantee``) → the tier this result *earned* on this input,
  demoted per-result when its runtime monitor did not confirm the precondition.
* **temporal** (``provenance.recognize``) → the ``when`` W and the ∀-validate half of the
  decision. Temporal state lives *beside* the DAG (architecture §6), so the caller
  recognizes the pattern against a :class:`~provenance.Trace` and hands the verdict in.
* **value** (``provenance.evaluate``) → upstream: whether the detector fired, which seeds
  the confidence leaf.

The decision is ``kjoin(detect, validate)``: a detector that fired (``TRUE`` ∃-detect) and
a temporal pattern that did not hold (``FALSE`` ∀-validate) fuse to ``BOTH`` — the carrier's
contradiction value *is* the soundness alarm, for free (architecture §5).

Home note: this lives in forge-core (where the detector ops live, and which already deps
``provenance``) and takes the ATT&CK ``technique`` as a plain string. When semantic technique
resolution (semantic-cyber) and a battery of detectors arrive, this graduates to its own
``packages/detection/`` layer. Today it is the thin vertical slice that proves the five
folds compose into the contract end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass

from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    Confidence,
    CustodyAttestation,
    Entity,
    Four,
    GuaranteeCertificate,
    Tier,
    confidence,
    custody,
    guarantee,
    kjoin,
)

# The carrier.md Belnap value → the schema's `belnap` enum string. Explicit (not
# repr-derived) so the contract projection never drifts if the carrier's repr changes.
_BELNAP: dict[Four, str] = {NONE: "none", TRUE: "true", FALSE: "false", BOTH: "both"}


@dataclass(frozen=True, slots=True)
class WRecord:
    """The five W's — the empirical grounding that turns a technique label into checkable
    telemetry facts. Each W is a Belnap-typed claim; an unanswered W is ``NONE``, never
    ``FALSE`` (absence of evidence ≠ evidence of absence). ``provenance`` is the CID of the
    DAG node this record is about."""

    who: Four
    what: Four
    when: Four
    where: Four
    how: Four
    provenance: str

    @property
    def score(self) -> float:
        """Aggregate W-confidence in [0, 1]: the fraction of the five W's confirmed ``TRUE``.

        Honest by construction — a ``NONE`` (unanswered) or ``FALSE`` W does not count toward
        grounding, so an unattributed detection scores low, not falsely high."""
        ws = (self.who, self.what, self.when, self.where, self.how)
        return sum(1 for w in ws if w == TRUE) / len(ws)


@dataclass(frozen=True, slots=True)
class DetectionVerdict:
    """The canonical detection unit. ``provenance`` is the root node's CID — the one object
    all the folds are interpretations of; full justification is reachable by walking it."""

    technique: str
    score: float
    decision: Four
    w_record: WRecord
    guarantee: GuaranteeCertificate
    custody: Four
    provenance: str

    def to_contract(self) -> dict:
        """Project into ``detection_verdict.schema.json`` JSON. Validated against the PINNED
        schema in the tests."""
        return {
            "technique": self.technique,
            "score": self.score,
            "decision": _BELNAP[self.decision],
            "w_record": {
                "who": _BELNAP[self.w_record.who],
                "what": _BELNAP[self.w_record.what],
                "when": _BELNAP[self.w_record.when],
                "where": _BELNAP[self.w_record.where],
                "how": _BELNAP[self.w_record.how],
                "score": self.w_record.score,
                "provenance": self.w_record.provenance,
            },
            "guarantee": {
                "subject_cid": self.guarantee.subject_cid,
                "tier": self.guarantee.tier.label,
            },
            "custody": _BELNAP[self.custody],
            "provenance": self.provenance,
        }


def assemble_verdict(
    root: Entity,
    *,
    technique: str,
    confidence_evidence: dict[str, Confidence],
    claims: dict[str, Tier],
    monitors: dict[str, Four] | None = None,
    attestations: dict[str, CustodyAttestation] | None = None,
    when: Four = NONE,
    who: Four = NONE,
    where: Four = NONE,
    how: Four = NONE,
) -> DetectionVerdict:
    """Assemble a :class:`DetectionVerdict` by folding the five concerns over ``root``'s DAG.

    Every fold reads the *same* content-addressed structure rooted at ``root``; the verdict
    is their projection at ``root.id``.

    * ``confidence_evidence`` / ``claims`` / ``monitors`` / ``attestations`` are the
      per-fold leaf inputs (see each fold's docstring), keyed by ``Entity.id``.
    * ``when`` is the temporal fold's verdict (``recognize(pattern, trace)``), passed in
      because temporal state lives beside the DAG, not in it.
    * ``who`` / ``where`` / ``how`` are the remaining W's, defaulting to ``NONE`` — an
      ungrounded W is honestly unknown, never a false negative.

    The ``decision`` is ``kjoin`` of the ∃-detect verdict (the confidence knowledge axis)
    with the ∀-validate verdict (``when``): agreement stays ``TRUE``/``FALSE``; disagreement
    surfaces as ``BOTH`` — the soundness alarm.
    """
    conf = confidence(root, evidence=confidence_evidence)[root.id]
    cust = custody(root, attestations=attestations)[root.id]
    cert = guarantee(root, claims=claims, monitors=monitors)[root.id]

    detect = conf.belnap  # ∃-detect: did the detector's evidence say fired?
    decision = kjoin(detect, when)  # fuse with the ∀-validate temporal verdict
    score = conf.probability if conf.probability is not None else 0.0

    w = WRecord(
        who=who,
        what=detect,  # the technique's artifact present? = the detector fired
        when=when,
        where=where,
        how=how,
        provenance=root.id,
    )
    return DetectionVerdict(
        technique=technique,
        score=score,
        decision=decision,
        w_record=w,
        guarantee=cert,
        custody=cust,
        provenance=root.id,
    )
