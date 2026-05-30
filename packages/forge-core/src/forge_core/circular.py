"""Circular statistics — the aggregations a CYCLIC signal is actually consumed by.

A CYCLIC signal's samples live on a circle of circumference ``period``: an angle,
a phase, a compass bearing, a time-of-day. Linear aggregations — the arithmetic
mean, the ordinary variance — are *wrong* on such data at the wrap boundary. The
arithmetic mean of two angles straddling the branch cut points at the
diametrically opposite side of the circle: ``mean(0.1, 2π−0.1) == π``, but the
two angles sit a hair either side of ``0``, so their true central tendency is
``0``, not ``π``. The correct aggregations embed each angle as a unit vector
``e^{i·2π·θ/period}``, average the vectors, and read back the *angle* and the
*length* of the resultant.

This module is what makes ``SignalKind.CYCLIC`` load-bearing rather than
decorative: the kind gate elsewhere (filters, energy, lock-in, CFAR) *rejects*
cyclic data from linear ops; here is where cyclic data is consumed correctly.

Math (Mardia & Jupp, *Directional Statistics*, §2.2):

    mean resultant  R̄ = | (1/n) Σ e^{iθ_k} |                  ∈ [0, 1]
    circular mean   Arg( Σ e^{iθ_k} )                          (an angle)
    circular var    V = 1 − R̄                                 ∈ [0, 1]

``R̄ == 1`` ⇔ all samples coincide (perfectly concentrated); ``R̄ == 0`` ⇔ no
preferred direction (antipodal or uniform). The circular variance is its
complement, so it is small for tight clusters and ``1`` for full dispersion —
unbounded linear variance has no place on a closed circle.

Wraps ``scipy.stats.circmean`` / ``circvar``, passing the signal's ``period``
through as the ``high`` boundary (``low=0``) so non-2π circles — degrees mod 360,
days mod 7 — aggregate correctly. scipy's ``circmean`` returns ``Arg`` in
``[0, period]`` (the boundary value ``period`` is the wrap-equivalent of ``0``).
"""
from __future__ import annotations

import numpy as np
from scipy.stats import circmean, circvar

from forge_core.signal import Signal, SignalKind


def _angles(signal: Signal) -> np.ndarray:
    """Gate to CYCLIC and reject empty input; return the angle array."""
    x = signal.require(SignalKind.CYCLIC).samples
    if x.size == 0:
        raise ValueError("circular statistic of an empty signal is undefined")
    return x


def circular_mean(signal: Signal) -> float:
    """Mean angle of a CYCLIC signal, in ``[0, period]``.

    ``Arg(Σ e^{i·2π·θ/period})`` scaled to the signal's circle — correct across
    the wrap boundary where the arithmetic mean is not. The returned value is the
    wrap-equivalent of itself ``mod period``; scipy may report the boundary
    ``period`` in place of ``0``.
    """
    x = _angles(signal)
    return float(circmean(x, high=signal.period, low=0.0))


def resultant_length(signal: Signal) -> float:
    """Mean resultant length ``R̄ ∈ [0, 1]`` of a CYCLIC signal.

    The magnitude of the averaged unit vectors: ``1`` when all angles coincide,
    ``0`` when they cancel (antipodal or uniform). A concentration measure — the
    circular analogue of inverse spread. Computed as ``1 − circular_variance``
    (scipy exposes the variance, not the resultant, directly).
    """
    return 1.0 - circular_variance(signal)


def circular_variance(signal: Signal) -> float:
    """Circular variance ``V = 1 − R̄ ∈ [0, 1]`` of a CYCLIC signal.

    ``0`` for perfectly concentrated angles, ``1`` for fully dispersed. The
    complement of :func:`resultant_length`.
    """
    x = _angles(signal)
    return float(circvar(x, high=signal.period, low=0.0))
