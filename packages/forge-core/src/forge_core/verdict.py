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
* **custody** (``provenance.custody`` + ``provenance.trustworthiness``) → the ingest
  *trustworthiness*: the digest-custody verdict (``TRUE`` only when keystone CID-equality holds
  on a signed, live source) knowledge-joined with the source's payload **validity**. Intact
  digest + malformed content → ``BOTH`` (the soundness alarm: faithfully delivered yet bunk).
  With no validity check the coupling is a no-op, so custody is the bare digest verdict.
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
    UNCHECKED,
    Confidence,
    CustodyAttestation,
    CustodyStep,
    Entity,
    Four,
    GuaranteeCertificate,
    Localization,
    Tier,
    Validity,
    confidence,
    custody,
    guarantee,
    kjoin,
    trustworthiness,
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
class Calibration:
    """Attached calibration evidence — the false-alarm-rate bound this detection's threshold was set
    against, and by which method. Surfaced so the verdict *carries* its FAR honesty (e.g. "FAR ≤ α,
    conformal, distribution-free") instead of leaving it implicit in the score/tier. Whether the bound
    actually *held* on this input is the guarantee tier's job (per-result demotion); this records the
    claim and the method, not a redesign of the guarantee system."""

    method: str  # "conformal" | "cfar" | "fdr"
    far_bound: float


@dataclass(frozen=True, slots=True)
class DetectionVerdict:
    """The canonical detection unit. ``provenance`` is the root node's CID — the one object
    all the folds are interpretations of; full justification is reachable by walking it.

    ``custody`` and ``validity`` are kept as **separate primitive dimensions** (integrity in
    transit; content well-formedness). ``trustworthiness`` is the **derived view** that
    ``kjoin``s them — not a primitive, and deliberately not folding in guarantee or confidence.
    Keeping the primitives separate (and carrying the validity *deviation*) preserves the
    information a single collapsed 'trust' bit would lose."""

    technique: str
    score: float
    decision: Four
    w_record: WRecord
    guarantee: GuaranteeCertificate
    custody: Four  # PRIMITIVE: the digest verdict (integrity in transit) — never reads content
    validity: Validity  # PRIMITIVE: source-payload well-formedness + the deviation
    trustworthiness: Four  # DERIVED VIEW: kjoin(custody, validity) — "is the chain sound"
    provenance: str
    # OPTIONAL explanatory structure — the custody-chain walk; "where do I look", not a scalar.
    custody_localization: Localization | None = None
    # OPTIONAL cross-check carrier — ``kjoin`` of the primary ∃-detect with an INDEPENDENT measure of the
    # same thing (a redundant primitive in its *check* role, e.g. distinct-count vs entropy for fan-out).
    # ``BOTH`` when the two disagree: the soundness alarm, for free. ``None`` = no cross-check supplied.
    # MECHANICS only — that a disagreement is operationally meaningful is a separate, deferred claim.
    cross_check: Four | None = None
    # OPTIONAL calibration evidence — the FAR bound + method the threshold was set against (attached so
    # the verdict carries its FAR honesty explicitly). ``None`` = uncalibrated (honest absence).
    calibration: Calibration | None = None

    def to_contract(self) -> dict:
        """Project into ``detection_verdict.schema.json`` JSON. Validated against the PINNED
        schema in the tests."""
        out = {
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
            "validity": {
                "verdict": _BELNAP[self.validity.verdict],
                "deviation": list(self.validity.deviation),  # the feature — no longer dropped
            },
            "trustworthiness": _BELNAP[self.trustworthiness],
            "provenance": self.provenance,
        }
        if self.custody_localization is not None:  # optional explanatory surface
            loc = self.custody_localization
            out["custody_localization"] = {
                "verdict": _BELNAP[loc.verdict],
                "suspect": list(loc.suspect),
                "exonerated": list(loc.exonerated),
                **({"seam_break": loc.seam_break} if loc.seam_break is not None else {}),
            }
        if self.cross_check is not None:  # optional redundant-measure cross-check (BOTH on disagreement)
            out["cross_check"] = _BELNAP[self.cross_check]
        if self.calibration is not None:  # optional FAR-bound + method, attached (honesty made explicit)
            out["calibration"] = {"method": self.calibration.method, "far_bound": self.calibration.far_bound}
        return out


def assemble_verdict(
    root: Entity,
    *,
    technique: str,
    confidence_evidence: dict[str, Confidence],
    claims: dict[str, Tier],
    monitors: dict[str, Four] | None = None,
    attestations: dict[str, CustodyAttestation] | None = None,
    chains: dict[str, tuple[CustodyStep, ...]] | None = None,
    localization: Localization | None = None,
    check: Four | None = None,
    calibration: Calibration | None = None,
    validity: Validity = UNCHECKED,
    when: Four = NONE,
    what: Four | None = None,
    who: Four = NONE,
    where: Four = NONE,
    how: Four = NONE,
) -> DetectionVerdict:
    """Assemble a :class:`DetectionVerdict` by folding the concerns over ``root``'s DAG.

    Every fold reads the *same* content-addressed structure rooted at ``root``; the verdict
    is their projection at ``root.id``.

    * ``confidence_evidence`` / ``claims`` / ``monitors`` / ``attestations`` are the
      per-fold leaf inputs (see each fold's docstring), keyed by ``Entity.id``.
    * ``chains`` maps a source id to a multi-hop ``CustodyStep`` chain (precedence over its
      attestation); ``localization`` is the optional explanatory ``Localization`` surface
      (``localize(chain, held)``) the caller emits — "where to look", populated when useful
      (typically ``trustworthiness`` in {``False``, ``Both``}). It is not a scalar and is not
      required; it summarizes the chain that lives in provenance.
    * ``validity`` is the source-payload well-formedness verdict. It is knowledge-joined into
      the custody field via :func:`~provenance.trustworthiness`, so intact digest-custody plus
      a *malformed* payload yields ``BOTH`` (the soundness alarm). Default ``UNCHECKED`` makes
      the coupling a no-op (custody = the bare digest verdict).
    * ``when`` is the temporal fold's verdict (``recognize(pattern, trace)``), passed in
      because temporal state lives beside the DAG, not in it.
    * ``what`` overrides the "artifact present?" W. Default (``None``) → the ∃-detect verdict.
      A caller routes a malformed source's *deviation* here as a feature: ``TRUE`` when the
      deviation matches the technique's signature (the malformation **is** the artifact),
      ``NONE`` when a needed field is unparseable (can't tell). **Never** a blanket ``FALSE`` —
      a malformed source is not silently dropped (that is the parser-evasion / absence-as-
      negative trap), and "couldn't validate" is ``NONE``, not "didn't happen".
    * ``who`` / ``where`` / ``how`` are the remaining W's, defaulting to ``NONE`` — an
      ungrounded W is honestly unknown, never a false negative.

    The ``decision`` is ``kjoin`` of the ∃-detect verdict (the confidence knowledge axis)
    with the ∀-validate verdict (``when``): agreement stays ``TRUE``/``FALSE``; disagreement
    surfaces as ``BOTH`` — the soundness alarm.
    """
    conf = confidence(root, evidence=confidence_evidence)[root.id]
    # `chains` (multi-hop custody) takes precedence per source; the scalar still folds by tmeet.
    digest_custody = custody(root, attestations=attestations, chains=chains)[root.id]
    cert = guarantee(root, claims=claims, monitors=monitors)[root.id]

    detect = conf.belnap  # ∃-detect: did the detector's evidence say fired?
    decision = kjoin(detect, when)  # fuse with the ∀-validate temporal verdict
    # cross-check: kjoin the primary detect with an INDEPENDENT redundant measure (if supplied) →
    # BOTH on disagreement. None when no check was supplied (the cross-check was not performed).
    cross = None if check is None else kjoin(detect, check)
    score = conf.probability if conf.probability is not None else 0.0
    # custody (digest) and validity stay separate primitives; trustworthiness is the derived view.
    trust = trustworthiness(digest_custody, validity)

    w = WRecord(
        who=who,
        what=detect if what is None else what,  # malformed-source deviation routes here as a feature
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
        custody=digest_custody,  # the bare digest verdict — primitive, not the synthesis
        validity=validity,
        trustworthiness=trust,
        provenance=root.id,
        custody_localization=localization,  # optional explanatory surface (where to look)
        cross_check=cross,  # optional redundant-measure agreement (BOTH on disagreement)
        calibration=calibration,  # optional FAR-bound + method, attached (None = uncalibrated)
    )
