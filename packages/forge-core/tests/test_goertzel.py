"""Goertzel single-frequency power tests.

Cover registration, the FFT-bin equivalence (the correctness anchor), tone
selectivity, sliding-window localisation, complex sidedness, the kind gate, and
parameter validation.
"""
import numpy as np
import pytest

from forge_core import goertzel
from forge_core import ops
from forge_core.signal import Signal, SignalKind

goertzel_op = ops.get("goertzel")


def _tone(f0: float, fs: float, n: int) -> np.ndarray:
    return np.sin(2 * np.pi * f0 * np.arange(n) / fs)


# ── registration ─────────────────────────────────────────────────────────────


def test_op_registered():
    assert "goertzel" in ops.registered()
    assert isinstance(ops.get("goertzel"), ops.Op)


# ── correctness anchor: integer-bin FFT equivalence ──────────────────────────


def test_matches_fft_bin():
    fs, n, k = 1.0, 64, 9            # integer bin k -> exact |X[k]|**2
    rng = np.random.default_rng(0)
    x = rng.standard_normal(n)
    out = goertzel_op(Signal(samples=x, fs=fs), freq=k * fs / n).value()  # whole signal
    fft_power = np.abs(np.fft.fft(x)[k]) ** 2
    assert out["power"].shape == (1,)
    assert out["power"][0] == pytest.approx(fft_power, rel=1e-6)


def test_matches_fft_bin_complex():
    fs, n, k = 1.0, 128, 20
    rng = np.random.default_rng(1)
    x = rng.standard_normal(n) + 1j * rng.standard_normal(n)
    out = goertzel_op(Signal(samples=x, fs=fs, kind=SignalKind.COMPLEX),
                      freq=k * fs / n).value()
    assert out["power"][0] == pytest.approx(np.abs(np.fft.fft(x)[k]) ** 2, rel=1e-6)


# ── selectivity ───────────────────────────────────────────────────────────────


def test_tone_selectivity():
    fs, f0, n = 1000.0, 137.0, 4096
    s = Signal(samples=_tone(f0, fs, n), fs=fs)
    on = goertzel_op(s, freq=f0).value()["power"][0]
    off = goertzel_op(s, freq=300.0).value()["power"][0]
    assert on > 1000 * off


def test_complex_is_signed():
    fs, f0, n = 1000.0, 50.0, 4096
    x = np.exp(2j * np.pi * f0 * np.arange(n) / fs)  # power at +f0 only
    s = Signal(samples=x, fs=fs, kind=SignalKind.COMPLEX)
    pos = goertzel_op(s, freq=f0).value()["power"][0]
    neg = goertzel_op(s, freq=-f0).value()["power"][0]
    assert pos > 1000 * neg


# ── sliding-window localisation ──────────────────────────────────────────────


def test_sliding_localises_burst():
    fs, f0, n, nperseg = 1000.0, 100.0, 4096, 256
    x = np.zeros(n)
    x[1024:1280] = _tone(f0, fs, 256)  # tone in exactly one (aligned) window
    out = goertzel_op(Signal(samples=x, fs=fs), freq=f0, nperseg=nperseg,
                      noverlap=0).value()
    burst_win = 1024 // nperseg
    p = out["power"]
    assert out["window_starts"][burst_win] == 1024
    assert p[burst_win] == p.max()
    # the burst window dominates the quiet ones
    assert p[burst_win] > 1000 * np.median(p)


def test_return_complex_coeff():
    s = Signal(samples=_tone(50.0, 1000.0, 1024), fs=1000.0)
    out = goertzel_op(s, freq=50.0, return_complex=True).value()
    assert np.iscomplexobj(out["coeff"])
    assert out["power"][0] == pytest.approx(np.abs(out["coeff"][0]) ** 2)


# ── gate & validation ─────────────────────────────────────────────────────────


def test_rejects_cyclic():
    s = Signal(samples=np.linspace(0, 6.0, 256), fs=1.0, kind=SignalKind.CYCLIC)
    with pytest.raises(TypeError):
        goertzel_op(s, freq=0.1)


def test_rejects_freq_above_nyquist():
    s = Signal(samples=_tone(10.0, 100.0, 256), fs=100.0)
    with pytest.raises(ValueError):
        goertzel_op(s, freq=60.0).value()  # > fs/2 = 50


def test_rejects_window_longer_than_signal():
    s = Signal(samples=_tone(10.0, 100.0, 128), fs=100.0)
    with pytest.raises(ValueError):
        goertzel_op(s, freq=10.0, nperseg=256).value()
