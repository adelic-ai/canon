"""Conformal anomaly detection — distribution-free false-alarm control (Axis B).

The decision layer (``detection.py``'s CFAR, ``changepoint.py``'s CUSUM) controls false alarms
*conditional on a noise model*: CFAR's closed-form ``Pfa`` assumes square-law/exponential
clutter, CUSUM's ARL a known pre-change distribution. That is exactly the wrong tool for the
information-theoretic features (``information.py``): entropy is bounded by ``log2(k)``, KL/MI
have no native rate at all, so a model-based threshold either mismatches (the entropy×CA-CFAR
finding: ``alpha`` calibrated for power statistics over-thresholds a bounded statistic) or
doesn't exist. Conformal supplies the missing leg — a **distribution-free, finite-sample**
false-alarm bound that holds for *any* statistic, the architecture's ``bounded`` guarantee for
the IT half of the battery grid (spine §4; ``web/index.html``).

**The construction** (split / inductive conformal, one-sided). Given a calibration set of
``n`` scores from known-normal data and a test score ``s``, the conformal p-value for the
upper tail ("large score = anomalous") is

    p(s) = (1 + #{i : c_i >= s}) / (n + 1).

Flag an anomaly when ``p(s) <= alpha``. The guarantee: for a fresh normal point *exchangeable*
with the calibration set, ``P(flag) = ⌊(n+1)·alpha⌋ / (n+1) <= alpha`` — marginal,
distribution-free, finite-sample, model-agnostic. No noise model, no asymptotics, no proof
assistant (spine §4: conformal is native Python). :func:`conformal_far_bound` returns the
realized ``⌊(n+1)·alpha⌋/(n+1)``.

**The assumption, named.** The bound is conditional on **exchangeability** (the normal
calibration and test points are exchangeable) — the conformal analog of CFAR's
homogeneous-reference-window. Confirming exchangeability *per input* (calibration not stale or
contaminated, no distribution shift) is active research and unbuilt (spine §9), so
:func:`conformal_guarantee_posture` defaults its monitor to a **recorded absence**: the
``bounded`` claim does not stand until a monitor confirms exchangeability, exactly as the
decode's ``machine_checked`` ceiling does not stand without a proof.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from provenance import NONE, Entity, Four, Tier

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind

_TAILS = ("upper", "lower")


def conformal_far_bound(n_cal: int, alpha: float) -> float:
    """The realized finite-sample false-alarm bound ``⌊(n_cal+1)·alpha⌋ / (n_cal+1)``.

    This is the *achievable* marginal Type-I rate of the conformal test — ``<= alpha`` always,
    and the exact rate when scores are continuous (no ties). It is the honest number to report
    as the detector's ``Pfa``: not the requested ``alpha`` but the rate the finite calibration
    set can actually deliver.
    """
    if n_cal < 1:
        raise ValueError(f"n_cal must be >= 1, got {n_cal}")
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    return float(np.floor((n_cal + 1) * alpha) / (n_cal + 1))


def conformal_pvalues(
    scores: np.ndarray, calibration: np.ndarray, *, tail: str = "upper"
) -> np.ndarray:
    """Conformal p-values of ``scores`` against a ``calibration`` set of normal scores.

    ``tail="upper"`` (large = anomalous): ``p = (1 + #{c >= s}) / (n+1)``.
    ``tail="lower"`` (small = anomalous): ``p = (1 + #{c <= s}) / (n+1)``.
    Computed by binary search over the sorted calibration set (vectorized over ``scores``). A
    non-finite score yields ``NaN`` (a no-decision, mirroring CFAR's NaN edge region), never a
    silent flag.
    """
    if tail not in _TAILS:
        raise ValueError(f"tail must be one of {_TAILS}, got {tail!r}")
    s = np.asarray(scores, dtype=np.float64)
    cal = np.asarray(calibration, dtype=np.float64)
    if cal.ndim != 1 or cal.size < 1:
        raise ValueError("calibration must be a non-empty 1-D array of normal scores")
    n = cal.size
    sorted_cal = np.sort(cal)

    p = np.full(s.shape, np.nan, dtype=np.float64)
    finite = np.isfinite(s)
    sf = s[finite]
    if tail == "upper":
        ge = n - np.searchsorted(sorted_cal, sf, side="left")  # #{c_i >= s}
        p[finite] = (1.0 + ge) / (n + 1.0)
    else:  # lower
        le = np.searchsorted(sorted_cal, sf, side="right")  # #{c_i <= s}
        p[finite] = (1.0 + le) / (n + 1.0)
    return p


@op("conformal_detect", accepts=(SignalKind.REAL,), inputs=("calibration",))
def conformal_detect(
    signal: Signal,
    calibration: np.ndarray,
    *,
    alpha: float = 0.01,
    tail: str = "upper",
    **_: Any,
) -> dict[str, Any]:
    """Conformal anomaly detection over a REAL statistic signal.

    Parameters
    ----------
    calibration:
        1-D array of the *same statistic* measured on known-normal data — the reference the
        test scores are ranked against (a provenance ``used`` edge, in the lineage).
    alpha:
        Target false-alarm rate. The realized bound is :func:`conformal_far_bound` (``<= alpha``).
    tail:
        ``"upper"`` (large statistic anomalous, e.g. an entropy fan-out spike) or ``"lower"``.

    Returns
    -------
    dict with ``pvalues`` (NaN where the statistic is non-finite), ``detections`` (``p <= alpha``
    mask), ``indices``, ``alpha``, ``far_bound`` (the distribution-free finite-sample guarantee),
    ``n_cal``, ``tail``.
    """
    x = signal.require(SignalKind.REAL).samples
    cal = np.asarray(calibration, dtype=np.float64)
    if cal.ndim != 1 or cal.size < 1:
        raise ValueError("calibration must be a non-empty 1-D array of normal scores")
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")

    pvalues = conformal_pvalues(x, cal, tail=tail)
    detections = np.isfinite(pvalues) & (pvalues <= alpha)
    return {
        "pvalues": pvalues,
        "detections": detections,
        "indices": np.flatnonzero(detections),
        "alpha": alpha,
        "far_bound": conformal_far_bound(cal.size, alpha),
        "n_cal": int(cal.size),
        "tail": tail,
    }


def conformal_guarantee_posture(
    node: Entity, *, exchangeability: Four = NONE
) -> tuple[dict[str, Tier], dict[str, Four]]:
    """The honest ``(claims, monitors)`` for a conformal detector node, for the guarantee fold.

    Conformal earns ``BOUNDED`` — a distribution-free, finite-sample FAR bound — but only when
    its precondition, **exchangeability** (the normal calibration and test points are
    exchangeable), holds on this input. That is an assumption-bearing tier, so the claim stands
    only on a confirming monitor. Confirming exchangeability per input (no stale/contaminated
    calibration, no distribution shift) is active research and unbuilt (spine §9), so the
    default ``exchangeability=NONE`` is a **recorded absence**: the guarantee fold demotes the
    node to ``WELL_FORMED`` and records the demotion. Pass ``exchangeability=TRUE`` when a
    monitor confirms it (mirroring CFAR's homogeneous-reference-window verdict); the node then
    stands at ``BOUNDED``.
    """
    return {node.id: Tier.BOUNDED}, {node.id: exchangeability}
