"""Welch PSD tests.

Cover registration, the REAL one-sided / COMPLEX two-sided contract, tone
localisation, band-power integration, the CYCLIC gate, and the nperseg clamp.
"""
import numpy as np
import pytest

from forge_core import Spectrum, welch_psd
from forge_core import ops
from forge_core.signal import Signal, SignalKind

welch_op = ops.get("welch")


def _tone(f0: float, fs: float, n: int) -> np.ndarray:
    t = np.arange(n) / fs
    return np.sin(2 * np.pi * f0 * t)


# ── registration & contract ──────────────────────────────────────────────────


def test_op_registered():
    assert "welch" in ops.registered()
    assert isinstance(ops.get("welch"), ops.Op)


def test_returns_spectrum_with_fs_and_method():
    s = Signal(samples=_tone(50.0, 1000.0, 4096), fs=1000.0)
    spec = welch_op(s, nperseg=1024)
    assert isinstance(spec, Spectrum)
    assert spec.fs == 1000.0
    assert spec.method == "welch"
    assert spec.frequencies.shape == spec.power.shape


def test_source_channel_from_meta():
    s = Signal(samples=_tone(50.0, 1000.0, 2048), fs=1000.0,
               meta={"channel": "eth0.pps"})
    assert welch_op(s, nperseg=512).source_channel == "eth0.pps"


# ── real one-sided / complex two-sided ───────────────────────────────────────


def test_real_is_one_sided():
    fs = 1000.0
    spec = welch_op(Signal(samples=_tone(50.0, fs, 4096), fs=fs), nperseg=1024)
    assert spec.frequencies.min() >= 0.0
    assert spec.frequencies.max() == pytest.approx(fs / 2, rel=1e-9)
    # one-sided length is nperseg//2 + 1
    assert spec.frequencies.size == 1024 // 2 + 1


def test_complex_is_two_sided_and_signed():
    fs, f0, n = 1000.0, 50.0, 4096
    t = np.arange(n) / fs
    x = np.exp(2j * np.pi * f0 * t)  # power at +f0 only
    spec = welch_op(Signal(samples=x, fs=fs, kind=SignalKind.COMPLEX),
                    nperseg=1024)
    assert spec.frequencies.size == 1024  # full two-sided
    assert spec.frequencies.min() < 0.0   # negative frequencies present
    pos = spec.power[np.argmin(np.abs(spec.frequencies - f0))]
    neg = spec.power[np.argmin(np.abs(spec.frequencies + f0))]
    assert pos > 100 * neg  # a positive-frequency exponential


# ── localisation & band power ────────────────────────────────────────────────


def test_dominant_frequency_finds_tone():
    fs, f0 = 1000.0, 137.0
    spec = welch_op(Signal(samples=_tone(f0, fs, 8192), fs=fs), nperseg=2048)
    assert spec.dominant_frequencies(top_k=1)[0] == pytest.approx(f0, abs=fs / 2048)
    assert spec.dominant_periods(top_k=1)[0] == pytest.approx(1.0 / f0, rel=0.02)


def test_band_power_concentrates_at_tone():
    fs, f0 = 1000.0, 50.0
    spec = welch_op(Signal(samples=_tone(f0, fs, 8192), fs=fs), nperseg=2048)
    in_band = spec.band_power(40.0, 60.0)
    out_band = spec.band_power(200.0, 220.0)
    assert in_band > 100 * out_band


def test_band_power_empty_band_is_zero():
    spec = welch_op(Signal(samples=_tone(50.0, 1000.0, 2048), fs=1000.0),
                    nperseg=512)
    assert spec.band_power(10_000.0, 20_000.0) == 0.0


# ── gate & clamp ──────────────────────────────────────────────────────────────


def test_rejects_cyclic():
    s = Signal(samples=np.linspace(0, 6.0, 512), fs=1.0, kind=SignalKind.CYCLIC)
    with pytest.raises(TypeError):
        welch_op(s)


def test_nperseg_clamped_to_signal_length():
    # nperseg > n must not raise; scipy clamps and we mirror it.
    s = Signal(samples=_tone(5.0, 100.0, 128), fs=100.0)
    spec = welch_op(s, nperseg=4096)
    assert spec.frequencies.size == 128 // 2 + 1
