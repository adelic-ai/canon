"""Sequential change detection — CUSUM.

CUSUM (cumulative sum control chart, Page 1954) is the canonical *sequential*
detector of a shift in a signal's mean. Where the energy detector and CFAR ask
"is there a burst in this window?", CUSUM asks "has the operating level
*changed*, and when?" — accumulating small per-sample deviations so that a
sustained shift, even one too gradual to breach any single-window threshold,
eventually trips the alarm. That makes it the natural complement to CFAR, whose
adaptive threshold *tracks* (and so misses) a slow ramp: CUSUM is built to catch
exactly that regime.

It is a forward recurrence — each state depends only on the previous state and
the new sample — so it is intrinsically online/streaming; applied to a whole
array here, it is the same algorithm run in batch.

Standardised two-sided tabular form. With reference mean ``target`` (mu0) and
scale ``sigma``, standardise ``z = (x - target) / sigma`` and accumulate:

    S_hi[t] = max(0, S_hi[t-1] + z[t] - k)      # detects an upward shift
    S_lo[t] = max(0, S_lo[t-1] - z[t] - k)      # detects a downward shift

An alarm fires when either sum exceeds the decision interval ``h``. The slack
``k`` (reference value, in sigma units) is conventionally half the shift you
want to detect quickly — ``k = 0.5`` targets a 1-sigma shift. ``h`` trades
detection delay against false-alarm rate; ``h = 4``–``5`` are standard. The
``k`` recursion is the Gaussian log-likelihood-ratio test for the mean-shift
hypothesis, which is why CUSUM is optimal (minimises detection delay at a given
false-alarm rate, Lorden 1971).

:func:`cusum_arl` gives the Siegmund (1985) average-run-length approximation —
the sizing knob: ARL0 (in-control, the mean samples-between-false-alarms) and
ARL1 (out-of-control, the mean detection delay) as a function of ``k``, ``h``,
and the standardised shift.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind

_MAD_TO_SIGMA = 1.4826  # MAD -> sigma consistency factor for the normal


# ── ARL sizing ───────────────────────────────────────────────────────────────


def cusum_arl(k: float, h: float, delta: float = 0.0) -> float:
    """Average run length of a one-sided CUSUM (Siegmund 1985 approximation).

    ``delta`` is the standardised mean shift (in sigma units). ``delta = 0``
    gives ARL0 (expected samples between false alarms, in control); ``delta > k``
    gives ARL1 (expected detection delay). The drift is ``Delta = delta - k``;
    at ``Delta == 0`` the approximation tends to ``(h + 1.166)**2``.
    """
    if k < 0:
        raise ValueError(f"k must be >= 0, got {k}")
    if h <= 0:
        raise ValueError(f"h must be > 0, got {h}")
    b = h + 1.166
    drift = delta - k
    if abs(drift) < 1e-9:
        return b * b
    return float((np.exp(-2.0 * drift * b) + 2.0 * drift * b - 1.0) / (2.0 * drift**2))


# ── op ───────────────────────────────────────────────────────────────────────


@op("cusum", accepts=(SignalKind.REAL,))
def cusum(
    signal: Signal,
    *,
    target: float | None = None,
    sigma: float | None = None,
    k: float = 0.5,
    h: float = 5.0,
    reset: bool = True,
    **_: Any,
) -> dict[str, Any]:
    """Two-sided tabular CUSUM over a REAL signal (Page 1954).

    Parameters
    ----------
    target:
        In-control reference mean ``mu0``. If ``None``, estimated as the median
        (robust to the post-change samples).
    sigma:
        Standard deviation used to standardise. If ``None``, estimated robustly
        as ``1.4826 * MAD`` (median absolute deviation).
    k:
        Slack / reference value in sigma units (half the shift to detect;
        default 0.5 targets a 1-sigma shift).
    h:
        Decision interval in sigma units (default 5.0). Larger ``h`` -> longer
        ARL0 (fewer false alarms) but longer detection delay.
    reset:
        If True (default), both accumulators reset to 0 after an alarm so the
        chart restarts and subsequent change points are detected. If False, the
        sums keep accumulating after the first alarm.

    Returns
    -------
    dict with keys ``s_hi`` / ``s_lo`` (the two accumulator series),
    ``upper`` / ``lower`` (per-sample alarm masks), ``alarms`` (either side),
    ``indices`` (alarm sample indices), ``direction`` (+1 up / -1 down / 0),
    plus the ``target``, ``sigma``, ``k``, ``h``, ``reset`` used.
    """
    x = signal.require(SignalKind.REAL).samples
    if k < 0:
        raise ValueError(f"k must be >= 0, got {k}")
    if h <= 0:
        raise ValueError(f"h must be > 0, got {h}")

    if target is None:
        target = float(np.median(x))
    if sigma is None:
        sigma = _MAD_TO_SIGMA * float(np.median(np.abs(x - np.median(x))))
        if sigma == 0.0:  # degenerate (e.g. constant/step data) -> fall back
            sigma = float(np.std(x))
    if sigma <= 0.0:
        raise ValueError(f"sigma must be > 0, got {sigma}")

    z = (x - target) / sigma
    n = z.size
    s_hi = np.empty(n, dtype=np.float64)
    s_lo = np.empty(n, dtype=np.float64)
    upper = np.zeros(n, dtype=bool)
    lower = np.zeros(n, dtype=bool)

    hi = lo = 0.0
    for t in range(n):
        hi = max(0.0, hi + z[t] - k)
        lo = max(0.0, lo - z[t] - k)
        if hi > h:
            upper[t] = True
            if reset:
                hi = lo = 0.0
        elif lo > h:
            lower[t] = True
            if reset:
                hi = lo = 0.0
        s_hi[t] = hi
        s_lo[t] = lo

    alarms = upper | lower
    direction = upper.astype(np.int8) - lower.astype(np.int8)
    return {
        "s_hi": s_hi,
        "s_lo": s_lo,
        "upper": upper,
        "lower": lower,
        "alarms": alarms,
        "indices": np.flatnonzero(alarms),
        "direction": direction,
        "target": target,
        "sigma": sigma,
        "k": k,
        "h": h,
        "reset": reset,
    }
