"""Shared verdict-emission — the one place an unattested-telemetry detection becomes a verdict.

Both detector families (fan-out, off-hours) project a detection into the canonical
:class:`~forge_core.DetectionVerdict` *identically*: a by-reference (unattested) source → a
structural root → ``assemble_verdict`` with ``custody = NONE``. This module extracts that **shared
behavior** — the duplication was concrete (`fanout_verdict` and `offhours_verdict` differed only in
the ref string and provenance params). It is deliberately **not** a shared `Binding` *ontology*: the
two binding shapes are too different to parent yet (abstract shared behavior before shared ontology;
wait for a third detector family to force a general binding, if one is earned at all).

The honesty the verdict model exists for lives here, in one place: an unsigned corpus is wired *by
reference* (no `CustodyAttestation`), so every verdict reports ``custody = NONE`` and (no payload
validity) ``trustworthiness = NONE`` while the detection itself stands (``decision = TRUE``, a score
from the rare conformal p-value). No faked attestation to inflate trust.
"""

from __future__ import annotations

import functools
from pathlib import Path

from forge_core import Calibration, DetectionVerdict, assemble_verdict
from provenance import (
    NO_EVIDENCE,
    NONE,
    TRUE,
    Confidence,
    CustodyAttestation,
    Entity,
    Four,
    Tier,
    derive_registered,
    evidence_digest,
    lineage,
    source,
)

def _structural(_p):
    """A placeholder kernel for a node the folds only render, never evaluate — the recipe
    `params` (not this callable) carry the content. One stable function so `derive_registered`
    sees the same code object across every `build_detection_root` call."""
    return None


_PD = 0.9  # nominal detection probability for the confidence leaf (no calibrated Pd per detector)
_SHAPES_DIR = Path(__file__).parents[4] / "contracts" / "shapes"
_DOMAIN_SHAPES = (_SHAPES_DIR / "detection.shapes.ttl", _SHAPES_DIR / "cross_model.shapes.ttl")


def build_detection_root(ref: str, params: dict, corroboration: dict | None = None,
                         *, evidence: "bytes | str | None" = None) -> Entity:
    """The detection layer's verdict **provenance root**: a by-reference source (unattested telemetry ⇒
    carries no integrity) + a structural ``detection`` derivation recording the recipe ``params``. The
    folds never *evaluate* it; it is the content-addressed node the verdict justifies. Named (not inlined)
    so its **well-formedness is mechanically checkable** — ``validate(build_detection_root(...)).conforms``
    runs the self-falsifying SHACL shapes over its PROV-O, earning the ``well_formed`` claim instead of
    asserting it. The same root :func:`emit_detection_verdict` builds, so the check never drifts from use.

    **Corroboration is a provenance EDGE, not a verdict field.** When an independent external witness (the
    deduped Sigma panel) corroborates, ``corroboration={"rules": [...], "votes": N, ...}`` wraps the
    detection root in a ``sigma_corroboration`` derivation that ``prov:used`` one entity per fired
    rule-class. The corroboration is then a relation to other artifacts in the lineage graph —
    ``to_prov``-able and queryable on demand — *not* overloaded onto the ``cross_check`` axis (which is a
    within-evidence redundant-measure check, a different epistemic relation). This is the representation
    that scales to N witnesses / M sources without amending the verdict contract.

    **Custody is earned at the source.** Default: a by-reference source (a trusted handle by ``ref``,
    no integrity) ⇒ custody ``NONE``. Pass ``evidence`` (the ingested bytes) to make the source an
    *evidence* source whose CID **is** the content digest — the keystone (one hash, three roles). Paired
    with a :class:`~provenance.CustodyAttestation` in :func:`emit_detection_verdict`, the custody fold can
    then earn ``TRUE`` (signed + digest-matched) instead of the unsigned-telemetry floor."""
    if evidence is not None:
        src = source(evidence, name=ref, evidence=True)  # content-addressed by the evidence digest (keystone)
    else:
        src = source(ref, name=ref)  # by-reference identity — carries NO integrity (unattested log)
    root = derive_registered("detection", _structural, (src,), params)  # structural; the folds never evaluate it
    if corroboration and corroboration.get("rules"):
        # the external witnesses, as related artifacts the corroboration `used` (a real PROV-O edge)
        rule_ents = [source(f"sigma-rule:{n}", name=f"sigma-rule:{n}", kind="sigma-rule", reference=True)
                     for n in corroboration["rules"]]  # reference data, not evidence — custody excludes it
        root = derive_registered("sigma_corroboration", _structural, (root, *rule_ents),
                      {"votes": corroboration["votes"], "classes": corroboration.get("classes"),
                       "technique": corroboration.get("technique"),
                       "logsource": corroboration.get("logsource")})
    return root


@functools.lru_cache(maxsize=1)
def _well_formed_shapes():
    """Generic PROV-O well-formedness (provenance) + canon's DETECTION-DOMAIN shapes, merged once.
    ``detection.shapes.ttl`` requires every op-plan to record its params (the re-derivable recipe);
    ``cross_model.shapes.ttl`` requires a ``sigma_corroboration`` to be backed by ≥1 sigma-rule witness
    it actually used (corroboration earned, not asserted) — so the earned tier checks per-op structure
    AND the cross-model corroboration invariant, not just generic PROV-O."""
    from provenance import well_formed_shapes
    g = well_formed_shapes()
    for shape in _DOMAIN_SHAPES:
        if shape.exists():
            g.parse(shape, format="turtle")
    return g


def _earned_well_formed(root: Entity) -> Tier:
    """EARN the well_formed tier by SHACL-validating the root's PROV-O against the GENERIC + detection-DOMAIN
    shapes — not assert it. ``conforms`` (both) → ``WELL_FORMED``; malformed (generic OR domain) → ``ABSENT``
    (no guarantee); the ``[rdf]`` extra absent → ``ABSENT`` (can't check ⇒ can't earn — honest, never a
    silent pass)."""
    try:
        from provenance import to_prov, validate_graph
    except ImportError:
        return Tier.ABSENT
    return Tier.WELL_FORMED if validate_graph(to_prov(root), _well_formed_shapes()).conforms else Tier.ABSENT


def emit_detection_verdict(
    ref: str,
    *,
    technique: str,
    pvalue: float,
    params: dict,
    tier: Tier | None = None,
    fired: bool = True,
    who: Four = TRUE,
    when: Four = NONE,
    what: Four | None = None,
    where: Four = NONE,
    how: Four = NONE,
    check: Four | None = None,
    calibration: Calibration | None = None,
    corroboration: dict | None = None,
    evidence: "bytes | str | None" = None,
    attestation: CustodyAttestation | None = None,
    track_custody: bool = True,
    exchangeability: Four | None = None,
) -> DetectionVerdict:
    """Project a detection into the canonical :class:`~forge_core.DetectionVerdict`.

    ``ref`` is the by-reference source identity (unattested telemetry ⇒ ``custody = NONE``);
    ``params`` are the provenance recipe params (recorded in lineage); ``pvalue`` is the detection's
    false-alarm rate, feeding the confidence leaf.

    **``when`` is EARNED-only.** It is the temporal ∀-validate fold's verdict (``recognize(pattern,
    trace)``), so it defaults to ``NONE`` — *a detector claims ``when = TRUE`` only by passing it, having
    actually run a temporal pattern check.* A detector that is "about time" (off-hours, coordination) but
    whose temporal-ness lives in its ∃-detect, not a separate ``recognize``, leaves ``when`` ``NONE``:
    that is honest, not a regression. (``who`` defaults ``TRUE`` because every current producer identifies
    its entity; ``what`` defaults to the ∃-detect; ``where``/``how`` default ``NONE``.) All are parameters
    so a detector that grounds more — or earns a higher tier — can say so honestly.

    **The guarantee tier is EARNED, not asserted.** With ``tier=None`` (default) it is the SHACL
    conformance of the verdict's PROV-O root: ``well_formed`` iff ``validate(root).conforms``, else
    ``ABSENT`` (and ``ABSENT`` if the ``[rdf]`` extra is absent — can't check ⇒ can't earn). A caller
    passes an explicit ``tier`` only with independent evidence for a higher one.

    ``corroboration`` (an independent external witness, e.g. the Sigma panel) is recorded as a PROVENANCE
    EDGE on the root, **not** on ``check`` — see :func:`build_detection_root`. ``check`` is reserved for a
    within-evidence redundant-measure cross-check (BOTH on disagreement); corroboration is one-sided and a
    relation to other artifacts, so it lives in the lineage graph.

    **Earned custody.** Default (``evidence=None``) keeps the unsigned-telemetry floor: a by-reference
    source ⇒ ``custody = NONE`` (no faked attestation). Pass ``evidence`` (the ingested bytes) to anchor
    the source on its content digest (the keystone), and ``attestation`` (a signed in-toto/DSSE projection
    — see :func:`detection.ingest.attest`) for the custody fold to verify: ``TRUE`` (signed + digest-match),
    ``FALSE`` (digest mismatch — tampered), ``NONE`` (unsigned / silent feed). Composition with
    corroboration is **resolved**: the corroboration's rule-source entities are marked ``reference=True``
    (knowledge applied to evidence, not evidence), so the custody fold EXCLUDES them — an attested +
    corroborated verdict earns custody ``TRUE`` (the rules don't drag it), and the corroboration edge stays
    in provenance. Reference-data integrity (is the rule itself tampered?) is a separate concern (analytic
    provenance), not evidence-custody.

    **Custody is precondition-gated.** ``track_custody=False`` (no attested feed in this deployment — the
    common case) PARKS the axis: custody + trustworthiness are omitted from the contract (a
    precondition-absent state distinct from an evaluated ``NONE``; the renderer shows ``parked``). The
    decision is never affected — same discipline as off-hours being registry-gated when its fields are absent.
    """
    root = build_detection_root(ref, params, corroboration, evidence=evidence)  # +corroboration/+evidence
    earned = tier if tier is not None else _earned_well_formed(root)  # EARN the tier via SHACL, not assert
    # Earned custody: an attestation vouches for the evidence source (keyed by its content digest = its CID).
    attestations = ({evidence_digest(evidence): attestation}
                    if evidence is not None and attestation is not None else None)
    # The SHACL conformance is a property of the WHOLE graph, so every derived node earns the tier; the
    # guarantee fold meets claims across the DAG, so claim each derived node (not just root) — otherwise
    # the corroboration-wrapped inner `detection` node is unclaimed and meets the tier down to ABSENT.
    claims = {e.id: earned for e in lineage(root) if e.producer is not None}
    # EARNED bounded: a conformal detector node can CLAIM bounded (a distribution-free FAR ≤ α bound), but
    # only stands on a confirming exchangeability monitor — and only over a SHACL-well-formed graph (else the
    # demotion floor would be asserted, not earned). The guarantee fold gates it: TRUE → bounded, NONE/FALSE
    # → demoted to well_formed with the demotion recorded. Claimed on the `detection` node (the statistical
    # test), not the corroboration wrapper.
    monitors = None
    if exchangeability is not None and earned == Tier.WELL_FORMED:
        det_id = next((e.id for e in lineage(root)
                       if e.producer is not None and e.producer.op_name == "detection"), root.id)
        claims[det_id] = Tier.BOUNDED
        monitors = {det_id: exchangeability}
    # ``fired`` is the ∃-detect leaf. ``True`` (default) → a fired detector leaf (evidence FOR ⇒
    # detect TRUE ⇒ decision TRUE), the historical behavior. ``False`` → NO_EVIDENCE (belnap NONE,
    # no log-odds) ⇒ detect NONE ⇒ decision NONE and score 0.0: an HONEST "the detector ran but the
    # observation channel structurally established no claim" — distinct from a fired FALSE (evidence
    # AGAINST). It is NOT ``from_detector(False)`` (which is REFUTED-shaped); a plane that cannot see is
    # NONE, not a negative. Additive + backward-compatible: default True reproduces the prior leaf exactly.
    detect_leaf = Confidence.from_detector(True, pd=_PD, pfa=pvalue) if fired else NO_EVIDENCE
    return assemble_verdict(
        root,
        technique=technique,
        confidence_evidence={root.id: detect_leaf},
        claims=claims,
        monitors=monitors,  # exchangeability monitor gating the BOUNDED claim (None → no bounded claim)
        attestations=attestations,  # earned custody: the signed ingest record for the evidence source
        track_custody=track_custody,  # False → park the axis (no attested feed): custody/trust omitted
        who=who,
        when=when,
        what=what,
        where=where,
        how=how,
        check=check,  # the independent redundant-measure decision → cross_check carrier (BOTH on disagreement)
        calibration=calibration,  # optional FAR-bound + method, attached to the verdict
    )
