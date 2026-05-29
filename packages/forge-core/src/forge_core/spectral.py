"""Spectral estimation — Welch power spectral density.

Per the wrapper-first principle (forge-core borrows proven algorithms wholesale
and reserves novelty for the organisation): this does not reimplement spectral
estimation, it wraps :func:`scipy.signal.welch` into the Op + Signal frame.

The Welch PSD (Welch 1967) is the segment-averaged periodogram, which estimates
the power spectral density defined by the Wiener-Khinchin theorem (Wiener 1930,
Khinchin 1934) — the Fourier transform of the autocorrelation of a wide-sense-
stationary signal. For REAL input the PSD is one-sided (conjugate symmetry of
the DFT collapses the negative frequencies); for COMPLEX input it is two-sided,
with independent positive- and negative-frequency content. ``scipy.signal.welch``
switches automatically on input dtype. CYCLIC signals are rejected — a PSD of raw
angular samples is meaningless without unwrapping.

Ported from ``forge.ops.spectral.WelchOp`` / ``forge.ops._results.Spectrum``.
Two idiom changes for forge-core: ``fs`` is read from the :class:`Signal` (it
carries its own sampling rate) rather than being an Op parameter, and the Op is
``@op``-registered by name. ``Spectrum.band_power`` is new — the integration hook
the band-limited energy detector (radiometer) will consume once it is wired.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy.signal import welch

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


@dataclass(frozen=True, slots=True)
class Spectrum:
    """Power spectral density: frequency-indexed power.

    Attributes
    ----------
    frequencies:
        Frequency bin centres in Hz (using the source ``Signal.fs``), shape
        ``(n_freqs,)``. One-sided ``[0, fs/2]`` for REAL input; two-sided in
        FFT order (DC, positive, then negative) for COMPLEX input.
    power:
        Power at each frequency, same shape as ``frequencies``.
    fs:
        Sampling frequency assumed during estimation.
    method:
        Estimator label (``"welch"``).
    source_channel:
        Channel name from the source signal's ``meta``, for lineage display.
    """

    frequencies: np.ndarray
    power: np.ndarray
    fs: float
    method: str
    source_channel: str

    def dominant_frequencies(self, top_k: int = 5) -> np.ndarray:
        """Top-k frequency bins by power, sorted high to low. Excludes DC."""
        idx = np.flatnonzero(self.frequencies != 0.0)
        order = idx[np.argsort(-self.power[idx])][:top_k]
        return self.frequencies[order]

    def dominant_periods(self, top_k: int = 5) -> np.ndarray:
        """Top-k periods (= 1/frequency) by power. Samples, or seconds if fs in Hz."""
        return 1.0 / self.dominant_frequencies(top_k=top_k)

    def band_power(self, f_lo: float, f_hi: float) -> float:
        """Integrate the PSD over the closed band ``[f_lo, f_hi]`` (in Hz).

        Trapezoidal integration over the bins falling in the band, evaluated on
        the frequency axis sorted ascending (so it is correct for the wrapped
        two-sided COMPLEX axis as well). This is the band-limited radiometer's
        test statistic: total power in a frequency band.
        """
        if f_hi < f_lo:
            raise ValueError(f"f_hi ({f_hi}) must be >= f_lo ({f_lo})")
        mask = (self.frequencies >= f_lo) & (self.frequencies <= f_hi)
        if not mask.any():
            return 0.0
        f = self.frequencies[mask]
        p = self.power[mask]
        order = np.argsort(f)
        return float(np.trapezoid(p[order], f[order]))


@op("welch")
def welch_psd(
    signal: Signal,
    *,
    nperseg: int = 256,
    noverlap: int | None = None,
    window: str = "hann",
    detrend: str | bool = "constant",
    **_: Any,
) -> Spectrum:
    """Welch's-method PSD over a REAL or COMPLEX signal (Welch 1967).

    Parameters
    ----------
    nperseg:
        Segment length. Silently clamped to the signal length when longer
        (mirroring ``scipy.signal.welch``).
    noverlap:
        Samples of overlap between segments; ``None`` lets scipy default to
        ``nperseg // 2``.
    window:
        Window function name passed to scipy (default ``"hann"``).
    detrend:
        Per-segment trend removal (default ``"constant"`` — subtract the mean).

    Returns
    -------
    Spectrum
        Frequencies in Hz (from ``signal.fs``), power, and lineage metadata.
    """
    signal.require(SignalKind.REAL, SignalKind.COMPLEX)
    values = signal.samples  # already float64 / complex128 per the kind gate
    nperseg = min(nperseg, signal.n)
    freqs, power = welch(
        values,
        fs=signal.fs,
        nperseg=nperseg,
        noverlap=noverlap,
        window=window,
        detrend=detrend,
    )
    return Spectrum(
        frequencies=np.asarray(freqs, dtype=np.float64),
        power=np.asarray(power, dtype=np.float64),
        fs=signal.fs,
        method="welch",
        source_channel=str(signal.meta.get("channel", "")),
    )
