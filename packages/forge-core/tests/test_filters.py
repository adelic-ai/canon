"""Filter tests — Butterworth, notch, band-power bank.

Attenuation is measured with an independent FFT bin power (not our own goertzel)
so the filter and the measurement don't share an implementation. Frequencies are
chosen to land on integer FFT bins.
"""
import numpy as np
import pytest

from forge_core import butter_filter, notch_filter, band_power_bank, EEG_BANDS
from forge_core import ops
from forge_core.signal import Signal, SignalKind

butter_op = ops.get("butter")
notch_op = ops.get("notch")
bank_op = ops.get("band_power_bank")


def _tone(f: float, fs: float, n: int) -> np.ndarray:
    return np.sin(2 * np.pi * f * np.arange(n) / fs)


def _bin_power(x: np.ndarray, f: float, fs: float) -> float:
    n = x.size
    k = round(f * n / fs)
    return float(np.abs(np.fft.rfft(x)[k]) ** 2)


# ── registration ─────────────────────────────────────────────────────────────


def test_ops_registered():
    for name in ("butter", "notch", "band_power_bank"):
        assert name in ops.registered()
        assert isinstance(ops.get(name), ops.Op)


# ── Butterworth ──────────────────────────────────────────────────────────────


def test_lowpass_attenuates_high_passes_low():
    fs, n = 500.0, 2000
    x = _tone(5.0, fs, n) + _tone(120.0, fs, n)
    out = butter_op(Signal(samples=x, fs=fs), cutoff=30.0, btype="lowpass")
    y = out.samples
    # low component preserved, high component crushed
    assert _bin_power(y, 5.0, fs) > 0.5 * _bin_power(x, 5.0, fs)
    assert _bin_power(y, 120.0, fs) < 1e-3 * _bin_power(x, 120.0, fs)


def test_highpass_attenuates_low():
    fs, n = 500.0, 2000
    x = _tone(5.0, fs, n) + _tone(120.0, fs, n)
    y = butter_op(Signal(samples=x, fs=fs), cutoff=30.0, btype="highpass").samples
    assert _bin_power(y, 120.0, fs) > 0.5 * _bin_power(x, 120.0, fs)
    assert _bin_power(y, 5.0, fs) < 1e-3 * _bin_power(x, 5.0, fs)


def test_bandpass_keeps_mid_only():
    fs, n = 500.0, 2000
    x = _tone(5.0, fs, n) + _tone(50.0, fs, n) + _tone(120.0, fs, n)
    y = butter_op(Signal(samples=x, fs=fs), cutoff=(30.0, 70.0),
                  btype="bandpass").samples
    assert _bin_power(y, 50.0, fs) > 0.4 * _bin_power(x, 50.0, fs)
    assert _bin_power(y, 5.0, fs) < 1e-2 * _bin_power(x, 5.0, fs)
    assert _bin_power(y, 120.0, fs) < 1e-2 * _bin_power(x, 120.0, fs)


def test_zero_phase_preserves_alignment():
    fs, n = 500.0, 2000
    x = _tone(10.0, fs, n)  # in passband of a 30 Hz lowpass
    zp = butter_op(Signal(samples=x, fs=fs), cutoff=30.0, zero_phase=True).samples
    causal = butter_op(Signal(samples=x, fs=fs), cutoff=30.0,
                       zero_phase=False).samples
    # zero-phase output stays in phase with the input; causal is delayed
    assert np.corrcoef(x, zp)[0, 1] > np.corrcoef(x, causal)[0, 1]
    assert np.corrcoef(x, zp)[0, 1] > 0.99


def test_butter_preserves_shape_and_kind():
    fs, n = 500.0, 1024
    s = Signal(samples=_tone(10.0, fs, n), fs=fs)
    out = butter_op(s, cutoff=30.0)
    assert out.kind is SignalKind.REAL
    assert out.fs == fs
    assert out.samples.shape == (n,)


def test_butter_accepts_complex():
    fs, n = 500.0, 1024
    x = _tone(10.0, fs, n) + 1j * _tone(10.0, fs, n)
    out = butter_op(Signal(samples=x, fs=fs, kind=SignalKind.COMPLEX),
                    cutoff=30.0)
    assert out.kind is SignalKind.COMPLEX


# ── notch ─────────────────────────────────────────────────────────────────────


def test_notch_removes_line_noise():
    fs, n = 500.0, 2000
    x = _tone(10.0, fs, n) + _tone(60.0, fs, n)  # signal + 60 Hz mains
    y = notch_op(Signal(samples=x, fs=fs), freq=60.0, q=30.0).samples
    assert _bin_power(y, 60.0, fs) < 1e-2 * _bin_power(x, 60.0, fs)
    assert _bin_power(y, 10.0, fs) > 0.5 * _bin_power(x, 10.0, fs)


# ── band-power bank ──────────────────────────────────────────────────────────


def test_band_power_bank_localises_to_alpha():
    fs, n = 256.0, 4096
    s = Signal(samples=_tone(10.0, fs, n), fs=fs)  # 10 Hz -> alpha band (8-13)
    powers = bank_op(s)
    assert set(powers) == set(EEG_BANDS)
    assert powers["alpha"] == max(powers.values())
    assert powers["alpha"] > 10 * powers["theta"]
    assert powers["alpha"] > 10 * powers["beta"]


def test_bank_custom_bands():
    fs, n = 200.0, 2048
    s = Signal(samples=_tone(30.0, fs, n), fs=fs)
    powers = bank_op(s, bands={"low": (5.0, 15.0), "mid": (25.0, 35.0)})
    assert powers["mid"] > 10 * powers["low"]


# ── gates & validation ───────────────────────────────────────────────────────


def test_rejects_cyclic():
    s = Signal(samples=np.linspace(0, 6.0, 512), fs=100.0, kind=SignalKind.CYCLIC)
    with pytest.raises(TypeError):
        butter_op(s, cutoff=10.0)


def test_cutoff_above_nyquist_raises():
    s = Signal(samples=_tone(5.0, 100.0, 512), fs=100.0)
    with pytest.raises(ValueError):
        butter_op(s, cutoff=60.0)  # > fs/2 = 50


def test_bank_band_above_nyquist_raises():
    # default gamma is 30-100; at fs=100 Nyquist is 50 -> gamma is invalid
    s = Signal(samples=_tone(5.0, 100.0, 1024), fs=100.0)
    with pytest.raises(ValueError):
        bank_op(s)


def test_notch_freq_above_nyquist_raises():
    s = Signal(samples=_tone(5.0, 100.0, 512), fs=100.0)
    with pytest.raises(ValueError):
        notch_op(s, freq=60.0)
