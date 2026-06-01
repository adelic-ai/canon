"""Information-theoretic features — the IT measurement layer (Axis A).

The detection battery is *features × tests*: an information-theoretic **feature** (this module)
piped into a detection-theoretic **test** (``detection.py``'s CFAR, ``changepoint.py``'s CUSUM).
Until now forge-core had a rich test layer sitting on a one-element feature layer — *count*.
Entropy, KL and MI — the features that make the IT side worth anything (``web/index.html``,
``project_it_detection_inference``) — were named but never wired in as inputs. This is the first
of them: **windowed Shannon entropy**, the feature behind the ``entropy × CFAR`` cell (sudden
fan-out spike — enumeration onset) and ``entropy × CUSUM`` (creeping fan-out).

The core :func:`shannon_entropy` is a faithful port of ``signalforge.signal._information.entropy``
(prior art, ``~/dev/pickering``): ``H = -Σ p·log2(p)`` over a count distribution, in bits.

Design note (why this is a *feature*, not a *test*). CFAR/CUSUM supply false-alarm control
(closed-form ``Pfa`` / ARL); a feature supplies the statistic they threshold. So in the
guarantee fold the entropy op is a non-test computation on the guarantee-critical chain — like
the ingest decode, it earns ``well_formed`` (a deterministic, metamorphic-testable reduction:
relabel-invariant, bounded by ``log2(k)``), not ``bounded``. Its ``log2``/division round-off
would need a Gappa-style bound to reach ``machine_checked`` (deferred). Consequence: an
``entropy × CFAR`` detection is ``well_formed``-capped by the *feature*, exactly as a
``count × CFAR`` one is capped by the *decode* — the cap is a property of having any unverified
computation on the chain, and a feature is one.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


def shannon_entropy(counts: np.ndarray) -> float:
    """Shannon entropy of a count distribution, in bits.

    ``H(X) = -Σ p·log2(p)``, ``p = counts / Σcounts``. Zeros are ignored (``0·log0 = 0``).
    ``0`` = perfectly concentrated, ``log2(k)`` = uniform over ``k`` symbols. A faithful port of
    ``signalforge.signal._information.entropy`` (prior art); the formula is the contract.
    """
    counts = np.asarray(counts, dtype=np.float64)
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-np.sum(p * np.log2(p)))


@op("windowed_entropy", accepts=(SignalKind.REAL,))
def windowed_entropy(
    signal: Signal, *, window: int, step: int = 1, **_: Any
) -> Signal:
    """Sliding-window Shannon entropy of a categorical stream → a REAL statistic Signal.

    The input ``signal`` carries **category codes** (entity ids, ports, destinations) as REAL
    samples — the labels whose per-window *spread* is the fan-out signal. For each window of
    ``window`` samples (hop ``step``) the codes are histogrammed (``np.unique``) and reduced to
    :func:`shannon_entropy`; the result is a REAL Signal of one entropy value per window, at
    ``fs/step``. A sudden rise in this series is an enumeration onset — exactly what a CFAR cell
    downstream thresholds against the local entropy floor.

    Codes are real-encoded integers; they are rounded to the nearest int before histogramming
    so distinct labels histogram distinctly. ``window``/``step`` are recipe params (they fix the
    op's content address). Raises if the stream is shorter than one window.
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
        _, seg_counts = np.unique(seg, return_counts=True)
        out[w] = shannon_entropy(seg_counts)

    return Signal(out, fs=signal.fs / step, kind=SignalKind.REAL, t0=signal.t0)
