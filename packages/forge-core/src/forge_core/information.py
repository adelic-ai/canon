"""Information-theoretic features — the IT measurement layer (Axis A).

The detection battery is *features × tests*: an information-theoretic **feature** (this module)
piped into a detection-theoretic **test** (``detection.py``'s CFAR, ``changepoint.py``'s CUSUM).
Until now forge-core had a rich test layer sitting on a one-element feature layer — *count*.
Entropy, KL and MI — the features that make the IT side worth anything (``web/index.html``,
``project_it_detection_inference``) — were named but never wired in as inputs. This is the first
of them: **windowed Shannon entropy**, the feature behind the ``entropy × CFAR`` cell (sudden
fan-out spike — enumeration onset) and ``entropy × CUSUM`` (creeping fan-out). :func:`windowed_kl`
adds the second — KL from a baseline, the ``KL × conformal`` cell (a distributional break).

The cores :func:`shannon_entropy` and :func:`kl_divergence` are faithful ports of
``signalforge.signal._information`` (prior art, ``~/dev/pickering``): ``H = -Σ p·log2(p)`` and
``D_KL(P||Q) = Σ p·log2(p/q)``, in bits.

A note on grain. Entropy needs no fixed alphabet (each window histograms itself), so it dodged
the binning decision; **KL is the first feature that forces it** — ``P`` (window) and ``Q``
(baseline) must share an aligned support. :func:`windowed_kl` makes that choice explicit
(alphabet ``[0,K)`` from the baseline, one bin per symbol, Lidstone smoothing); a
lattice/ScalePlan-principled binning is the deferred next fork.

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


def kl_divergence(p_counts: np.ndarray, q_counts: np.ndarray) -> float:
    """KL divergence ``D_KL(P || Q) = Σ p·log2(p/q)`` in bits — "how far is P from baseline Q".

    Faithful port of ``signalforge.signal._information.kl_divergence``: normalizes both count
    arrays, sums only where *both* are positive, returns ``inf`` on disjoint support. **Not
    symmetric.** Note the port's both-positive masking silently drops P-mass on symbols Q never
    saw — which is exactly the novelty a detector wants to *see*, so the windowed detection
    feature (:func:`windowed_kl`) smooths instead of masking. This bare primitive is kept for the
    unsmoothed prior-art contract; detection uses the smoothed path.
    """
    p = np.asarray(p_counts, dtype=np.float64)
    q = np.asarray(q_counts, dtype=np.float64)
    p_total, q_total = p.sum(), q.sum()
    if p_total <= 0 or q_total <= 0:
        return 0.0
    p_norm, q_norm = p / p_total, q / q_total
    mask = (p_norm > 0) & (q_norm > 0)
    if not mask.any():
        return float("inf")
    return float(np.sum(p_norm[mask] * np.log2(p_norm[mask] / q_norm[mask])))


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


@op("windowed_kl", accepts=(SignalKind.REAL,), inputs=("baseline",))
def windowed_kl(
    signal: Signal,
    baseline: np.ndarray,
    *,
    window: int,
    step: int = 1,
    smoothing: float = 0.5,
    **_: Any,
) -> Signal:
    """Sliding-window KL divergence of a categorical stream from a baseline → a REAL statistic.

    For each window of ``window`` codes (hop ``step``) the codes are histogrammed over a **fixed
    alphabet** ``[0, K)`` — where ``K = len(baseline)`` — and the window distribution ``P`` is
    scored against the baseline distribution ``Q`` (the ``baseline`` counts) as
    ``D_KL(P || Q)`` in bits. A distributional break — a window whose mass shifts onto symbols
    rare in the baseline — spikes the series, which conformal then thresholds.

    **The binning decision, made explicit (this is the first feature that forces it).** KL needs
    ``P`` and ``Q`` over a *common, aligned support*, so the op fixes three things the caller and
    the design had so far deferred:

    * **alphabet** — the symbol set is exactly ``[0, K)``, *defined by the baseline's length*.
      Codes outside it raise (an out-of-alphabet event is a real signal, but folding it into an
      OOV bin is a separate decision — flagged, not silently bucketed here).
    * **bins** — one bin per symbol (``np.bincount(minlength=K)``); no coarsening. A lattice /
      ScalePlan-principled binning (``lattice.py``) is the deferred next fork, not wired yet.
    * **smoothing** — additive (Lidstone) ``smoothing`` on *both* ``P`` and ``Q`` (default 0.5,
      the Jeffreys/Krichevsky–Trofimov prior) so ``q > 0`` on every symbol. This keeps a novel
      symbol's divergence *finite and large* instead of ``inf`` (or, worse, silently dropped as
      the bare :func:`kl_divergence` mask would) — novelty must be seen, not erased.
    """
    signal.require(SignalKind.REAL)
    if window < 1:
        raise ValueError(f"window must be >= 1, got {window}")
    if step < 1:
        raise ValueError(f"step must be >= 1, got {step}")
    if smoothing <= 0.0:
        raise ValueError(f"smoothing must be > 0 (a defined support needs q>0), got {smoothing}")
    q = np.asarray(baseline, dtype=np.float64)
    if q.ndim != 1 or q.size < 1:
        raise ValueError("baseline must be a non-empty 1-D count vector over the alphabet [0, K)")
    n_symbols = q.size
    codes = np.rint(signal.samples).astype(np.int64)
    if codes.size < window:
        raise ValueError(
            f"stream too short: need >= {window} samples for one window, got {codes.size}"
        )
    if codes.size and (codes.min() < 0 or codes.max() >= n_symbols):
        raise ValueError(
            f"codes must lie in the declared alphabet [0, {n_symbols}); "
            f"got range [{int(codes.min())}, {int(codes.max())}]"
        )

    q_smoothed = q + smoothing
    q_norm = q_smoothed / q_smoothed.sum()

    n_windows = (codes.size - window) // step + 1
    out = np.empty(n_windows, dtype=np.float64)
    for w in range(n_windows):
        seg = codes[w * step : w * step + window]
        p = np.bincount(seg, minlength=n_symbols).astype(np.float64) + smoothing
        p /= p.sum()
        out[w] = float(np.sum(p * np.log2(p / q_norm)))

    return Signal(out, fs=signal.fs / step, kind=SignalKind.REAL, t0=signal.t0)
