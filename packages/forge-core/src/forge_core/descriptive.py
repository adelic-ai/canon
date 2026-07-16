"""Descriptive-statistics features — the non-IT corner of Axis A.

Alongside ``information.py``'s entropy / KL / MI, the detection battery's measurement axis has a
descriptive-statistics family that reads the *same* per-window category histogram with a cheaper,
log-free lens:

* **cardinality** — :func:`distinct_count`: how many distinct symbols a window saw. The
  ``distinct-count × CFAR`` cell surfaces a novel-entity / fan-out spike directly (16 destinations
  where there is usually one), no probabilities involved.
* **concentration** — :func:`herfindahl` (HHI, ``Σ p_i²``): how much mass one symbol holds. The
  ``HHI × CFAR`` cell catches a concentration spike ("one account doing everything"). HHI is
  entropy's mass-view mirror — ``1`` when one symbol owns the window, ``1/k`` when uniform, exactly
  when Shannon entropy is ``0`` and ``log2(k)`` respectively.

Like :func:`~forge_core.information.windowed_entropy`, the windowed ops are relabel-invariant
reductions of a per-window histogram of a REAL category-code stream → a REAL statistic ``Signal``
that a CFAR / CUSUM cell thresholds. As unverified computations on the guarantee-critical chain they
earn ``well_formed`` (deterministic, bounded, metamorphic-testable), not ``bounded`` — the same cap
windowed_entropy carries, and for the same reason.

Deferred: the Gini *inequality* coefficient (degenerate over a self-histogram — a single category
has no inequality among its one symbol; it wants a fixed alphabet, like ``windowed_kl``) and the
spread family (MAD, CoV), which operates on continuous values rather than category codes — a
different feature shape.
"""

from __future__ import annotations

from typing import Any, Callable

import numpy as np

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


def distinct_count(codes: np.ndarray) -> int:
    """Number of distinct symbols in a category-code array. ``0`` for an empty array."""
    codes = np.asarray(codes)
    if codes.size == 0:
        return 0
    return int(np.unique(codes).size)


def herfindahl(counts: np.ndarray) -> float:
    """Herfindahl–Hirschman concentration ``HHI = Σ p_i²``, ``p = counts / Σcounts``.

    ``1`` = one symbol holds all the mass (max concentration), ``1/k`` = uniform over ``k`` symbols.
    The mass-view mirror of :func:`~forge_core.information.shannon_entropy` (HHI ``1`` ⇔ entropy
    ``0``). ``0`` for an empty / all-zero distribution.
    """
    counts = np.asarray(counts, dtype=np.float64)
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts / total
    return float(np.sum(p * p))


def _windowed(
    signal: Signal, window: int, step: int, reduce: Callable[[np.ndarray, np.ndarray], float]
) -> Signal:
    """Sliding-window driver shared by the descriptive ops (mirrors windowed_entropy's contract).

    Histograms each window of REAL category codes and applies ``reduce(symbols, counts) -> float``,
    emitting a REAL statistic ``Signal`` of one value per window at ``fs/step``.
    """
    signal.require(SignalKind.REAL)
    if window < 1:
        raise ValueError(f"window must be >= 1, got {window}")
    if step < 1:
        raise ValueError(f"step must be >= 1, got {step}")
    codes = np.rint(signal.samples).astype(np.int64)
    if codes.size < window:
        raise ValueError(
            f"stream too short: need >= {window} samples for one window, got {codes.size}"
        )
    n_windows = (codes.size - window) // step + 1
    out = np.empty(n_windows, dtype=np.float64)
    for w in range(n_windows):
        seg = codes[w * step : w * step + window]
        symbols, counts = np.unique(seg, return_counts=True)
        out[w] = reduce(symbols, counts)
    return Signal(out, fs=signal.fs / step, kind=SignalKind.REAL, t0=signal.t0)


@op("windowed_distinct", accepts=(SignalKind.REAL,))
def windowed_distinct(signal: Signal, *, window: int, step: int = 1, **_: Any) -> Signal:
    """Sliding-window distinct-symbol count of a categorical stream → a REAL statistic Signal.

    Per window of ``window`` category codes (hop ``step``), the number of distinct symbols. A sudden
    rise is a fan-out / novel-entity spike — the feature behind ``distinct-count × CFAR``.
    ``window`` / ``step`` are recipe params (they fix the op's content address).
    """
    return _windowed(signal, window, step, lambda symbols, counts: float(symbols.size))


@op("windowed_herfindahl", accepts=(SignalKind.REAL,))
def windowed_herfindahl(signal: Signal, *, window: int, step: int = 1, **_: Any) -> Signal:
    """Sliding-window Herfindahl (HHI) concentration of a categorical stream → a REAL Signal.

    Per window, ``Σ p_i²`` over the window's symbol counts — ``1`` when one symbol dominates, ``1/k``
    when uniform. The concentration feature behind ``HHI × CFAR`` ("one account doing everything");
    the mass-view mirror of windowed_entropy.
    """
    return _windowed(signal, window, step, lambda symbols, counts: herfindahl(counts))
