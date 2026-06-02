"""Off-hours detection — the second detector *family*: temporal/circular, a soft anomaly.

Fan-out (``fanout.py``) is ``entity → distribution over values``, a *hard* anomaly: a 20-account
spray is unambiguous, so the detected set matches the labels exactly and precision is measurable.
Off-hours is a different family — ``entity → distribution over time-of-day``, with **circular
statistics** instead of entropy — and a different *kind* of anomaly: **soft / graded**. A
business-hours user appearing at 03:00 is suspicious, but ordinary people occasionally work late, so
"off-hours" activity is partially-labeled by nature. This module exists to make the architecture
handle graded evidence honestly, not just clean benchmark wins (see ``README.md`` for the validation
regime).

The detector is a **compound** that reuses three forge-core primitives:

* **concentration gate** — ``resultant_length`` (circular R) + ``circular_mean``: an account is in
  scope only if it has a *business-hours routine* (R ≥ ``r_min`` and a mean hour inside business
  hours). This excludes 24/7 service accounts — which have no "normal hours", so "off-hours" is
  undefined for them — and is what gives the detector its specificity.
* **circular anomaly** — each event's off-hours-ness is its circular distance from the *population*
  business-hours mean; ``conformal_pvalues`` (upper tail) scores it against the population, so a
  deep-night event is rare → low p. Flag gated-account events with ``p ≤ alpha``.

A note on the binding. Off-hours does **not** fit ``FanoutBinding`` — there is no value to fan out
over and no time-bin grain; instead a per-account concentration gate over a circular feature. That
is a genuinely different binding shape (:class:`TemporalBinding`), and having two concrete binding
shapes is what would *force* a general ``Binding`` abstraction — if one is earned at all.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from forge_core import (
    DetectionVerdict,
    assemble_verdict,
    circular_mean,
    conformal_pvalues,
    resultant_length,
)
from forge_core.signal import Signal, SignalKind
from provenance import TRUE, Confidence, Tier, derive, source

from detection.fanout import load_kerberos_events

_PD = 0.9  # nominal detection probability for the confidence leaf
_MIN_HISTORY = 10  # an account needs this many events before a circular routine is meaningful


@dataclass(frozen=True, slots=True)
class TemporalBinding:
    """A named temporal-anomaly binding — the off-hours analog of
    :class:`~detection.fanout.FanoutBinding`, and a *different binding shape*.

    Shares ``name`` / ``entity_field`` / ``technique`` / ``alpha`` with the fan-out binding, but its
    detector-specific parameters are the **concentration gate** (``r_min`` resultant length and the
    ``business_hours`` window the mean must fall in), not a value field and a grain. Two concrete
    binding shapes now exist; whether a general ``Binding`` is earned is the open question they pose.
    """

    name: str
    entity_field: str
    technique: str
    r_min: float = 0.5
    business_hours: tuple[int, int] = (8, 18)
    alpha: float = 0.02


#: A business-hours-concentrated account active in the deep night. ATT&CK T1078 (Valid Accounts):
#: anomalous-timing use of an otherwise-legitimate account.
OFF_HOURS = TemporalBinding(name="off-hours", entity_field="Account_Name", technique="T1078")


@dataclass(frozen=True, slots=True)
class OffHoursDetection:
    """A flagged off-hours event: the ``entity``, the event ``hour`` (0–24), its conformal
    ``pvalue`` (rarity vs the population's hour distribution), and the event time ``at`` (epoch s)."""

    entity: str
    hour: float
    pvalue: float
    at: float


def _hour_of_day(seconds: float) -> float:
    """Hour-of-day (0–24) from epoch seconds. ``load_kerberos_events`` measures time from a midnight
    epoch, so ``seconds % 86400`` is the time-into-day."""
    return (seconds % 86400) / 3600.0


def _angles(hours: np.ndarray) -> Signal:
    """Hours-of-day as a CYCLIC :class:`~forge_core.Signal` on the 24-hour circle (period 2π)."""
    return Signal(2 * np.pi * np.asarray(hours, dtype=np.float64) / 24.0, fs=1.0, kind=SignalKind.CYCLIC)


def _circular_distance(a: np.ndarray, b: float) -> np.ndarray:
    """Shortest angular distance (radians) between angles ``a`` and a reference angle ``b``."""
    d = np.abs(np.asarray(a) - b) % (2 * np.pi)
    return np.minimum(d, 2 * np.pi - d)


def detect_offhours(
    events: "list[tuple[float, str, str]]", binding: TemporalBinding
) -> dict:
    """Detect off-hours activity: gate accounts by circular concentration, then flag deep-night
    events by conformal rarity against the population's hour distribution.

    ``events`` are ``(seconds, entity, _value)`` (the value is unused). Returns ``detections`` (one
    :class:`OffHoursDetection` per flagged event), ``gated`` (the in-scope, business-hours-routined
    entities — the ones the detector even *considers*; service accounts are gated out), ``binding``.
    """
    per: dict[str, list[float]] = defaultdict(list)
    for seconds, entity, _value in events:
        per[entity].append(seconds)
    if not per:
        raise ValueError("no events")

    all_angles = _angles([_hour_of_day(s) for s, _, _ in events]).samples
    pop_mean = circular_mean(_angles([_hour_of_day(s) for s, _, _ in events]))
    stat_all = _circular_distance(all_angles, pop_mean)  # off-hours-ness of every event (calibration)
    lo, hi = binding.business_hours

    detections: list[OffHoursDetection] = []
    gated: list[str] = []
    for entity, secs in per.items():
        if len(secs) < _MIN_HISTORY:
            continue
        angs = _angles([_hour_of_day(s) for s in secs])
        r = resultant_length(angs)
        mean_hour = (circular_mean(angs) % (2 * np.pi)) * 24.0 / (2 * np.pi)
        if r < binding.r_min or not (lo <= mean_hour <= hi):
            continue  # no business-hours routine (e.g. a 24/7 service account) → off-hours undefined
        gated.append(entity)

        stat = _circular_distance(angs.samples, pop_mean)
        pvalues = conformal_pvalues(stat, stat_all, tail="upper")
        for sec, p in zip(secs, pvalues):
            if p <= binding.alpha:
                detections.append(
                    OffHoursDetection(entity=entity, hour=_hour_of_day(sec), pvalue=float(p), at=sec)
                )
    return {"detections": detections, "gated": gated, "binding": binding, "alpha": binding.alpha}


def run_offhours(path: str, binding: TemporalBinding = OFF_HOURS) -> dict:
    """Load a Kerberos corpus and run :func:`detect_offhours` under ``binding``."""
    events = load_kerberos_events(
        path, entity_field=binding.entity_field, value_field=binding.entity_field
    )
    return detect_offhours(events, binding)


def offhours_verdict(detection: OffHoursDetection, binding: TemporalBinding) -> DetectionVerdict:
    """Emit the canonical :class:`~forge_core.DetectionVerdict` for one off-hours detection.

    Same honesty as the fan-out path: the corpus is an unsigned CSV, so the source is wired by
    reference (no attestation) and the verdict reports ``custody = NONE`` / ``trustworthiness =
    NONE`` while the detection stands (``decision = TRUE``, a score from the rare conformal p). The
    W-record grounds who (the account) and when (the off-hours time); what is the ∃-detect; where /
    how stay ``NONE``. Tier ``WELL_FORMED`` (circular conformal over an unattested ingest)."""
    ref = f"{binding.name}|{detection.entity}|{detection.at:.0f}"
    src = source(ref, name=ref)  # by-reference — unattested log, no integrity
    root = derive(
        "offhours_detect",
        lambda _p: None,
        (src,),
        {"entity": detection.entity, "hour": round(detection.hour, 2), "technique": binding.technique},
    )
    return assemble_verdict(
        root,
        technique=binding.technique,
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=detection.pvalue)},
        claims={root.id: Tier.WELL_FORMED},
        who=TRUE,  # the account is identified
        when=TRUE,  # the off-hours time is known
    )


def offhours_verdicts(result: dict) -> "list[DetectionVerdict]":
    """One :class:`~forge_core.DetectionVerdict` per off-hours detection in a :func:`run_offhours`
    result."""
    binding = result["binding"]
    return [offhours_verdict(d, binding) for d in result["detections"]]
