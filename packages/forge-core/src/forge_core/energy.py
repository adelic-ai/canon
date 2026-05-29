"""Energy detector (radiometer) — the unknown-signal detector.

When nothing about a signal is known — not its shape, not its frequency, only
that energy *might* be present in an observation window — the optimal detector
under a Gaussian-noise model is the **energy detector** (Urkowitz 1967): sum the
squared samples in the window and compare to a threshold. It is the bottom rung
of the detection ladder by prior knowledge (energy detector → Goertzel/lock-in →
matched filter); cheapest and most general, but non-coherent, so it needs the
most SNR to fire.

The math (square-law, white Gaussian noise of variance ``sigma**2``):

    H0 (noise only)      sum(x**2) / sigma**2  ~  chi2(df = N)
    H1 (signal present)  sum(x**2) / sigma**2  ~  ncx2(df = N, nc = E_s / sigma**2)

where ``N`` is the window length and ``E_s`` the signal energy. The decision
threshold for a target false-alarm probability ``Pfa`` is the upper-tail chi2
quantile ``gamma = chi2.isf(Pfa, N)`` on the normalised statistic ``T = E / sigma**2``;
the detection probability for a given non-centrality is ``Pd = ncx2.sf(gamma, N, nc)``.

This module produces the energy *statistic* per sliding window and applies the
fixed chi2 threshold. That statistic is exactly the kind of REAL, non-negative
series the CFAR layer in :mod:`forge_core.detection` thresholds adaptively — use
the energy detector when the noise variance is known/stationary, hand its
``statistic`` series to CA/OS-CFAR when the noise floor drifts.

Deferred: the band-limited radiometer (integrate a Welch PSD over a frequency
band) needs a ``WelchOp`` in forge-core, which is not yet ported from
``~/dev/forge``. This module is the time-domain form.

Wraps ``scipy.stats.chi2`` / ``ncx2`` for the threshold and power math; the
windowing is pure numpy.
"""
from __future__ import annotations

from typing import Any

import numpy as np
from scipy.stats import chi2, ncx2

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


# ── threshold & power math ───────────────────────────────────────────────────


def energy_threshold(nperseg: int, pfa: float) -> float:
    """Energy-detector decision threshold on the normalised statistic.

    ``gamma = chi2.isf(pfa, df=nperseg)`` — the value ``T = E / sigma**2``
    exceeds under H0 with probability ``pfa``. Monotonically decreasing in
    ``pfa``.
    """
    if nperseg < 1:
        raise ValueError(f"nperseg must be >= 1, got {nperseg}")
    if not 0.0 < pfa < 1.0:
        raise ValueError(f"pfa must be in (0, 1), got {pfa}")
    return float(chi2.isf(pfa, df=nperseg))


def energy_pd(nperseg: int, pfa: float, ncp: float) -> float:
    """Detection probability at non-centrality ``ncp = E_s / sigma**2``.

    ``Pd = ncx2.sf(gamma, df=nperseg, nc=ncp)`` where ``gamma`` is
    :func:`energy_threshold`. At ``ncp == 0`` this reduces to ``pfa`` (no
    signal, so Pd == Pfa); it increases monotonically with ``ncp``.
    """
    if ncp < 0:
        raise ValueError(f"ncp must be >= 0, got {ncp}")
    gamma = energy_threshold(nperseg, pfa)
    return float(ncx2.sf(gamma, df=nperseg, nc=ncp))


# ── op ───────────────────────────────────────────────────────────────────────


@op("energy_detector")
def energy_detector(
    signal: Signal,
    *,
    nperseg: int = 256,
    noverlap: int | None = None,
    noise_var: float | None = None,
    pfa: float = 1e-3,
    **_: Any,
) -> dict[str, Any]:
    """Sliding-window energy detector over a REAL signal.

    Parameters
    ----------
    nperseg:
        Window length ``N`` (= chi2 degrees of freedom).
    noverlap:
        Samples of overlap between consecutive windows; defaults to
        ``nperseg // 2``. The window step is ``nperseg - noverlap``.
    noise_var:
        Known noise variance ``sigma**2``. If ``None``, it is estimated
        robustly from the window energies: ``sigma**2 = median(E) /
        chi2.median(nperseg)``, which is unbiased under H0 and resistant to the
        minority of windows that actually contain signal. Prefer passing a known
        value when one is available.
    pfa:
        Target probability of false alarm.

    Returns
    -------
    dict with keys ``window_starts`` (sample index of each window), ``energy``
    (raw ``E_k = sum x**2``), ``statistic`` (``T_k = E_k / sigma**2``),
    ``threshold`` (scalar gamma on the normalised statistic), ``detections``
    (bool mask over windows), ``indices`` (window indices where detected),
    ``noise_var`` (the sigma**2 used), ``nperseg``, ``noverlap``, ``pfa``.
    """
    x = signal.require(SignalKind.REAL).samples
    n = x.size
    if nperseg < 1:
        raise ValueError(f"nperseg must be >= 1, got {nperseg}")
    if nperseg > n:
        raise ValueError(f"nperseg ({nperseg}) exceeds signal length ({n})")
    if noverlap is None:
        noverlap = nperseg // 2
    if not 0 <= noverlap < nperseg:
        raise ValueError(
            f"noverlap must be in [0, {nperseg}), got {noverlap}"
        )
    step = nperseg - noverlap

    windows = np.lib.stride_tricks.sliding_window_view(x, nperseg)[::step]
    window_starts = np.arange(0, n - nperseg + 1, step)
    energy = np.einsum("ij,ij->i", windows, windows)  # row-wise sum of squares

    if noise_var is None:
        noise_var = float(np.median(energy) / chi2.median(df=nperseg))
    if noise_var <= 0:
        raise ValueError(f"noise_var must be > 0, got {noise_var}")

    statistic = energy / noise_var
    gamma = energy_threshold(nperseg, pfa)
    detections = statistic > gamma

    return {
        "window_starts": window_starts,
        "energy": energy,
        "statistic": statistic,
        "threshold": gamma,
        "detections": detections,
        "indices": np.flatnonzero(detections),
        "noise_var": noise_var,
        "nperseg": nperseg,
        "noverlap": noverlap,
        "pfa": pfa,
    }
