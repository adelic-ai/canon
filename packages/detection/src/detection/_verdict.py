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
from provenance import NONE, TRUE, Confidence, Four, Tier, derive, source

_PD = 0.9  # nominal detection probability for the confidence leaf (no calibrated Pd per detector)


def emit_detection_verdict(
    ref: str,
    *,
    technique: str,
    pvalue: float,
    params: dict,
    tier: Tier = Tier.WELL_FORMED,
    who: Four = TRUE,
    when: Four = TRUE,
    what: Four | None = None,
    where: Four = NONE,
    how: Four = NONE,
    check: Four | None = None,
    calibration: Calibration | None = None,
) -> DetectionVerdict:
    """Project a detection into the canonical :class:`~forge_core.DetectionVerdict`.

    ``ref`` is the by-reference source identity (unattested telemetry ⇒ ``custody = NONE``);
    ``params`` are the provenance recipe params (recorded in lineage); ``pvalue`` is the detection's
    false-alarm rate, feeding the confidence leaf. The W-record and ``tier`` default to the common
    case (who/when grounded, ``what`` = the ∃-detect, ``WELL_FORMED`` over an unattested ingest) but
    are parameters so a detector that grounds more — or earns a higher tier — can say so honestly.
    """
    src = source(ref, name=ref)  # by-reference identity — carries NO integrity (unattested log)
    root = derive("detection", lambda _p: None, (src,), params)  # structural; the folds never evaluate it
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
