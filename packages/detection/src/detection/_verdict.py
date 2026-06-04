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

from forge_core import Calibration, DetectionVerdict, assemble_verdict
from provenance import NONE, TRUE, Confidence, Entity, Four, Tier, derive, source

_PD = 0.9  # nominal detection probability for the confidence leaf (no calibrated Pd per detector)


def build_detection_root(ref: str, params: dict) -> Entity:
    """The detection layer's verdict **provenance root**: a by-reference source (unattested telemetry ⇒
    carries no integrity) + a structural ``detection`` derivation recording the recipe ``params``. The
    folds never *evaluate* it; it is the content-addressed node the verdict justifies. Named (not inlined)
    so its **well-formedness is mechanically checkable** — ``validate(build_detection_root(...)).conforms``
    runs the self-falsifying SHACL shapes over its PROV-O, earning the ``well_formed`` claim instead of
    asserting it. The same root :func:`emit_detection_verdict` builds, so the check never drifts from use."""
    src = source(ref, name=ref)  # by-reference identity — carries NO integrity (unattested log)
    return derive("detection", lambda _p: None, (src,), params)  # structural; the folds never evaluate it


def emit_detection_verdict(
    ref: str,
    *,
    technique: str,
    pvalue: float,
    params: dict,
    tier: Tier = Tier.WELL_FORMED,
    who: Four = TRUE,
    when: Four = NONE,
    what: Four | None = None,
    where: Four = NONE,
    how: Four = NONE,
    check: Four | None = None,
    calibration: Calibration | None = None,
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
    """
    root = build_detection_root(ref, params)  # the verdict's provenance root (SHACL-checkable)
    return assemble_verdict(
        root,
        technique=technique,
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pvalue)},
        claims={root.id: tier},
        who=who,
        when=when,
        what=what,
        where=where,
        how=how,
        check=check,  # the independent redundant-measure decision → cross_check carrier (BOTH on disagreement)
        calibration=calibration,  # optional FAR-bound + method, attached to the verdict
    )
