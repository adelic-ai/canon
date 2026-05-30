"""CFAR detection — adaptive-threshold layer over a test statistic.

CFAR (Constant False-Alarm Rate) is the *threshold* layer of a detector, not a
detector itself. The signal statistic — a periodogram bin series, a matched-filter
output, an energy/radiometer series — is computed upstream; CFAR then sets the
decision threshold *adaptively from the local noise floor* so the false-alarm
probability ``Pfa`` stays constant even as the background drifts. In cyber
telemetry the "background" is a host's normal connection-rate baseline, which is
non-stationary across time-of-day and host role — exactly the drift CFAR is
built for.

The input ``Signal`` carries the test statistic in its samples: REAL and
non-negative (a squared envelope / power series). Both ops slide a reference
window of ``train`` cells on each side of the cell under test (CUT), separated
from the CUT by ``guard`` cells so a wide target cannot leak into its own noise
estimate. Cells too near the array edge to hold a full two-sided window get a
NaN threshold and no detection (no-decision region).

Two variants, differing only in how the reference cells are reduced to a noise
estimate:

CA-CFAR (cell-averaging)
    Noise estimate = mean of the ``N = 2·train`` reference cells. Closed-form
    multiplier ``alpha = N·(Pfa**(-1/N) - 1)`` (square-law / exponential
    clutter; Richards, *Fundamentals of Radar Signal Processing*). Cheap O(n)
    via cumsum. Optimal in homogeneous noise but *over-thresholds* (misses) when
    a second target or a clutter edge sits inside the reference window — i.e.
    when two C2 channels run concurrently or the traffic regime changes
    mid-window.

OS-CFAR (ordered-statistic)
    Noise estimate = the ``rank``-th smallest of the ``N`` reference cells
    (Rohling 1983). The multiplier ``alpha`` solves
    ``Pfa = prod_{i=0}^{rank-1} (N - i) / (alpha + N - i)`` numerically. Robust
    precisely where CA-CFAR fails — interfering targets and clutter edges — at
    higher compute cost (a sliding order statistic). For multi-beacon hosts,
    OS-CFAR is the safer default.

Pure numpy: CA-CFAR uses the cumsum-vectorisation pattern; OS-CFAR uses
``sliding_window_view`` + ``np.partition``. No scipy dependency.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


# ── threshold multipliers ────────────────────────────────────────────────────


def ca_cfar_alpha(num_ref: int, pfa: float) -> float:
    """CA-CFAR threshold multiplier for ``num_ref`` reference cells.

    Closed form ``alpha = N·(Pfa**(-1/N) - 1)`` under the square-law /
    exponential-clutter model. Monotonically decreasing in ``pfa``.
    """
    if num_ref < 1:
        raise ValueError(f"num_ref must be >= 1, got {num_ref}")
    if not 0.0 < pfa < 1.0:
        raise ValueError(f"pfa must be in (0, 1), got {pfa}")
    return num_ref * (pfa ** (-1.0 / num_ref) - 1.0)


def _os_pfa(alpha: float, num_ref: int, rank: int) -> float:
    """Pfa of an OS-CFAR detector at multiplier ``alpha``.

    ``Pfa = prod_{i=0}^{rank-1} (N - i) / (alpha + N - i)`` — monotonically
    decreasing in ``alpha`` (Rohling 1983, square-law / exponential clutter).
    """
    p = 1.0
    for i in range(rank):
        p *= (num_ref - i) / (alpha + num_ref - i)
    return p


def os_cfar_alpha(
    num_ref: int, rank: int, pfa: float, *, tol: float = 1e-10
) -> float:
    """OS-CFAR threshold multiplier solving ``_os_pfa(alpha) == pfa``.

    Bisection on the monotone Pfa(alpha) curve. ``rank`` is 1-based into the
    sorted reference cells (1 = smallest, ``num_ref`` = largest).
    """
    if num_ref < 1:
        raise ValueError(f"num_ref must be >= 1, got {num_ref}")
    if not 1 <= rank <= num_ref:
        raise ValueError(f"rank must be in [1, {num_ref}], got {rank}")
    if not 0.0 < pfa < 1.0:
        raise ValueError(f"pfa must be in (0, 1), got {pfa}")

    # Pfa(0) == 1 > pfa; grow the upper bound by doubling until Pfa < pfa.
    lo, hi = 0.0, 1.0
    while _os_pfa(hi, num_ref, rank) > pfa:
        hi *= 2.0
    # Bisect for the root.
    while hi - lo > tol * max(1.0, hi):
        mid = 0.5 * (lo + hi)
        if _os_pfa(mid, num_ref, rank) > pfa:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


# ── shared window validation ─────────────────────────────────────────────────


def _validate(signal: Signal, guard: int, train: int) -> np.ndarray:
    """Gate the signal and window geometry; return the real sample array."""
    signal.require(SignalKind.REAL)
    if guard < 0:
        raise ValueError(f"guard must be >= 0, got {guard}")
    if train < 1:
        raise ValueError(f"train must be >= 1, got {train}")
    half = guard + train
    if signal.n < 2 * half + 1:
        raise ValueError(
            f"signal too short: need >= {2 * half + 1} samples for "
            f"guard={guard}, train={train}, got {signal.n}"
        )
    return signal.samples


# ── ops ──────────────────────────────────────────────────────────────────────


@op("ca_cfar", accepts=(SignalKind.REAL,))
def ca_cfar(
    signal: Signal,
    *,
    guard: int = 2,
    train: int = 8,
    pfa: float = 1e-3,
    **_: Any,
) -> dict[str, Any]:
    """Cell-averaging CFAR over a REAL test-statistic signal.

    Parameters
    ----------
    guard:
        Guard cells per side, excluded from the noise estimate.
    train:
        Reference (training) cells per side; ``num_ref = 2·train``.
    pfa:
        Target probability of false alarm.

    Returns
    -------
    dict with keys ``threshold`` (NaN in the edge no-decision region),
    ``detections`` (bool mask), ``indices`` (where detections is True),
    ``alpha``, ``num_ref``, ``pfa``.
    """
    x = _validate(signal, guard, train)
    n = x.size
    half = guard + train
    num_ref = 2 * train
    alpha = ca_cfar_alpha(num_ref, pfa)

    # cumsum-vectorised reference sums: csum[j] == sum(x[:j]).
    csum = np.concatenate(([0.0], np.cumsum(x, dtype=np.float64)))
    cut = np.arange(half, n - half)
    lead = csum[cut - guard] - csum[cut - guard - train]
    lag = csum[cut + guard + train + 1] - csum[cut + guard + 1]
    noise = (lead + lag) / num_ref

    threshold = np.full(n, np.nan, dtype=np.float64)
    threshold[cut] = alpha * noise
    detections = np.zeros(n, dtype=bool)
    detections[cut] = x[cut] > threshold[cut]

    return {
        "threshold": threshold,
        "detections": detections,
        "indices": np.flatnonzero(detections),
        "alpha": alpha,
        "num_ref": num_ref,
        "pfa": pfa,
    }


@op("os_cfar", accepts=(SignalKind.REAL,))
def os_cfar(
    signal: Signal,
    *,
    guard: int = 2,
    train: int = 8,
    rank: int | None = None,
    pfa: float = 1e-3,
    **_: Any,
) -> dict[str, Any]:
    """Ordered-statistic CFAR over a REAL test-statistic signal.

    Like :func:`ca_cfar` but the noise estimate is the ``rank``-th smallest of
    the ``num_ref = 2·train`` reference cells, making it robust to interfering
    targets inside the reference window. ``rank`` defaults to ``round(0.75·N)``,
    a common robust choice; it is 1-based (1 = smallest).
    """
    x = _validate(signal, guard, train)
    n = x.size
    half = guard + train
    num_ref = 2 * train
    if rank is None:
        rank = max(1, int(round(0.75 * num_ref)))
    alpha = os_cfar_alpha(num_ref, rank, pfa)

    # Full two-sided windows; drop the central CUT+guards to leave the
    # 2·train reference cells, then take the rank-th order statistic.
    width = 2 * half + 1
    windows = np.lib.stride_tricks.sliding_window_view(x, width)
    ref_mask = np.ones(width, dtype=bool)
    ref_mask[half - guard : half + guard + 1] = False  # CUT + 2·guard cells
    ref = windows[:, ref_mask]
    kth = np.partition(ref, rank - 1, axis=1)[:, rank - 1]

    cut = np.arange(half, n - half)
    threshold = np.full(n, np.nan, dtype=np.float64)
    threshold[cut] = alpha * kth
    detections = np.zeros(n, dtype=bool)
    detections[cut] = x[cut] > threshold[cut]

    return {
        "threshold": threshold,
        "detections": detections,
        "indices": np.flatnonzero(detections),
        "alpha": alpha,
        "num_ref": num_ref,
        "rank": rank,
        "pfa": pfa,
    }
