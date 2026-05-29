"""Filters — Butterworth IIR, line-noise notch, band-power filter bank.

Wrappers over ``scipy.signal`` (wrapper-first principle). This is the borrow-
list's Wave-1: zero-phase filtering plus line-noise removal is the EEG entry
tax, and the same low-pass is what lock-in detection and the matched-filter
prewhitener will consume downstream.

Three ops, all signal -> signal (or, for the bank, signal -> band powers):

butter
    Butterworth IIR filter (low/high/band-pass, band-stop). Designed as
    second-order sections (``output="sos"``) for numerical stability at higher
    orders. Applied **zero-phase** by default via ``sosfiltfilt`` (forward-
    backward, no group delay — the EEG requirement); ``zero_phase=False`` gives
    the causal single-pass ``sosfilt`` when latency matters more than alignment.

notch
    Narrow IIR notch (``iirnotch``) for mains/line-noise removal (50/60 Hz and
    harmonics), applied zero-phase by default. The quality factor ``q`` sets the
    notch bandwidth ``= freq / q``.

band_power_bank
    Band-pass the signal into a set of named frequency bands and return the mean
    power in each — the canonical EEG feature. Defaults to the clinical EEG
    bands (delta/theta/alpha/beta/gamma).

REAL and COMPLEX inputs are accepted (the IIR coefficients are real; scipy's
forward-backward filtering handles complex samples, which is what lock-in's
post-mixing low-pass needs). CYCLIC is rejected — filtering raw angles is
meaningless.
"""
from __future__ import annotations

from typing import Any

import numpy as np
from scipy.signal import butter, filtfilt, iirnotch, lfilter, sosfilt, sosfiltfilt

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind

# Clinical EEG bands (Hz). Standard ranges; gamma upper edge varies by source.
EEG_BANDS: dict[str, tuple[float, float]] = {
    "delta": (0.5, 4.0),
    "theta": (4.0, 8.0),
    "alpha": (8.0, 13.0),
    "beta": (13.0, 30.0),
    "gamma": (30.0, 100.0),
}

_SCALAR_BTYPES = {"lowpass", "highpass"}
_BAND_BTYPES = {"bandpass", "bandstop"}


def _check_band(lo: float, hi: float, nyq: float, label: str) -> None:
    if not 0.0 < lo < hi:
        raise ValueError(f"{label}: need 0 < lo < hi, got ({lo}, {hi})")
    if hi >= nyq:
        raise ValueError(f"{label}: hi ({hi}) must be < Nyquist ({nyq})")


@op("butter")
def butter_filter(
    signal: Signal,
    *,
    cutoff: float | tuple[float, float],
    btype: str = "lowpass",
    order: int = 4,
    zero_phase: bool = True,
    **_: Any,
) -> Signal:
    """Butterworth IIR filter over a REAL or COMPLEX signal.

    Parameters
    ----------
    cutoff:
        Corner frequency in Hz: a scalar for ``"lowpass"``/``"highpass"``, a
        ``(lo, hi)`` pair for ``"bandpass"``/``"bandstop"``.
    btype:
        One of ``"lowpass"``, ``"highpass"``, ``"bandpass"``, ``"bandstop"``.
    order:
        Filter order (per band edge). Default 4.
    zero_phase:
        True (default) applies ``sosfiltfilt`` (forward-backward, zero group
        delay). False applies the causal ``sosfilt``.
    """
    x = signal.require(SignalKind.REAL, SignalKind.COMPLEX).samples
    nyq = signal.fs / 2.0
    if order < 1:
        raise ValueError(f"order must be >= 1, got {order}")
    if btype in _SCALAR_BTYPES:
        if not np.isscalar(cutoff):
            raise ValueError(f"{btype} needs a scalar cutoff, got {cutoff!r}")
        if not 0.0 < float(cutoff) < nyq:
            raise ValueError(f"cutoff ({cutoff}) must be in (0, {nyq})")
        wn: Any = float(cutoff)
    elif btype in _BAND_BTYPES:
        lo, hi = cutoff  # type: ignore[misc]
        _check_band(float(lo), float(hi), nyq, btype)
        wn = (float(lo), float(hi))
    else:
        raise ValueError(f"unknown btype {btype!r}")

    sos = butter(order, wn, btype=btype, fs=signal.fs, output="sos")
    y = sosfiltfilt(sos, x) if zero_phase else sosfilt(sos, x)
    return signal.with_samples(y)


@op("notch")
def notch_filter(
    signal: Signal,
    *,
    freq: float,
    q: float = 30.0,
    zero_phase: bool = True,
    **_: Any,
) -> Signal:
    """Narrow IIR notch at ``freq`` Hz (line-noise removal) over REAL/COMPLEX.

    ``q`` is the quality factor; the notch bandwidth is ``freq / q``.
    """
    x = signal.require(SignalKind.REAL, SignalKind.COMPLEX).samples
    nyq = signal.fs / 2.0
    if not 0.0 < freq < nyq:
        raise ValueError(f"freq ({freq}) must be in (0, {nyq})")
    if q <= 0:
        raise ValueError(f"q must be > 0, got {q}")
    b, a = iirnotch(freq, q, fs=signal.fs)
    y = filtfilt(b, a, x) if zero_phase else lfilter(b, a, x)
    return signal.with_samples(y)


@op("band_power_bank")
def band_power_bank(
    signal: Signal,
    *,
    bands: dict[str, tuple[float, float]] | None = None,
    order: int = 4,
    **_: Any,
) -> dict[str, float]:
    """Mean power per frequency band — the canonical EEG band-power feature.

    Band-passes the signal (zero-phase Butterworth) into each named band and
    returns ``{name: mean(y**2)}``. ``bands`` defaults to :data:`EEG_BANDS`; all
    band edges must lie below Nyquist.
    """
    x = signal.require(SignalKind.REAL).samples
    nyq = signal.fs / 2.0
    bands = EEG_BANDS if bands is None else bands
    powers: dict[str, float] = {}
    for name, (lo, hi) in bands.items():
        _check_band(float(lo), float(hi), nyq, name)
        sos = butter(order, (lo, hi), btype="bandpass", fs=signal.fs, output="sos")
        y = sosfiltfilt(sos, x)
        powers[name] = float(np.mean(np.abs(y) ** 2))
    return powers
