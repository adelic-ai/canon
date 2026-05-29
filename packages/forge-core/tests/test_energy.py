"""Energy-detector (radiometer) tests.

Cover the chi2 threshold / ncx2 power math, the windowing geometry, the robust
noise-variance estimate, the REAL kind gate, and the headline behaviour: a
high-energy burst breaches the threshold while quiet windows stay below it.
"""
import numpy as np
import pytest
from scipy.stats import chi2

from forge_core import energy_threshold, energy_pd
from forge_core import ops
from forge_core.signal import Signal, SignalKind

energy_op = ops.get("energy_detector")


# ── threshold & power math ───────────────────────────────────────────────────


def test_threshold_matches_chi2_isf():
    assert energy_threshold(64, 1e-3) == pytest.approx(chi2.isf(1e-3, df=64))


def test_threshold_decreases_with_higher_pfa():
    assert energy_threshold(64, 1e-1) < energy_threshold(64, 1e-4)


def test_pd_equals_pfa_at_zero_noncentrality():
    # No signal -> detection probability collapses to the false-alarm rate.
    assert energy_pd(64, 1e-3, 0.0) == pytest.approx(1e-3, rel=1e-6)


def test_pd_increases_with_noncentrality():
    assert energy_pd(64, 1e-3, 200.0) > energy_pd(64, 1e-3, 50.0)
    assert energy_pd(64, 1e-3, 50.0) > energy_pd(64, 1e-3, 0.0)


def test_math_input_validation():
    with pytest.raises(ValueError):
        energy_threshold(64, 1.0)
    with pytest.raises(ValueError):
        energy_pd(64, 1e-3, -1.0)


# ── registration ─────────────────────────────────────────────────────────────


def test_op_registered():
    assert "energy_detector" in ops.registered()
    assert isinstance(ops.get("energy_detector"), ops.Op)


# ── geometry & gate ──────────────────────────────────────────────────────────


def test_window_geometry():
    x = np.zeros(1000)
    out = energy_op(Signal(samples=x, fs=1.0), nperseg=100, noverlap=50,
                    noise_var=1.0)
    # step = 50; starts 0,50,...,900  -> 19 windows
    assert out["window_starts"][0] == 0
    assert out["window_starts"][-1] == 900
    assert out["energy"].shape == out["statistic"].shape == (19,)
    assert out["window_starts"].shape == (19,)


def test_rejects_non_real():
    s = Signal(samples=np.ones(512, dtype=complex), fs=1.0,
               kind=SignalKind.COMPLEX)
    with pytest.raises(TypeError):
        energy_op(s, nperseg=64)


def test_rejects_window_longer_than_signal():
    with pytest.raises(ValueError):
        energy_op(Signal(samples=np.ones(50), fs=1.0), nperseg=64)


def test_rejects_bad_overlap():
    with pytest.raises(ValueError):
        energy_op(Signal(samples=np.ones(512), fs=1.0), nperseg=64,
                  noverlap=64)


# ── behaviour ─────────────────────────────────────────────────────────────────


def test_detects_energy_burst():
    rng = np.random.default_rng(0)
    nperseg = 128
    x = rng.standard_normal(2048)              # unit-variance noise
    # burst aligned to a window boundary so it lands in exactly one window
    x[1024:1152] += rng.standard_normal(128) * 6.0
    out = energy_op(Signal(samples=x, fs=1.0), nperseg=nperseg, noverlap=0,
                    noise_var=1.0, pfa=1e-4)
    burst_win = 1024 // nperseg  # window covering the burst (noverlap=0)
    assert out["detections"][burst_win]
    # quiet windows stay below threshold at this Pfa
    quiet = np.delete(out["detections"], burst_win)
    assert not quiet.any()


def test_auto_noise_var_estimate():
    # Without an explicit noise_var, the robust median estimate should recover
    # the true variance and still flag the burst.
    rng = np.random.default_rng(1)
    nperseg = 128
    x = rng.standard_normal(4096) * 2.0        # sigma**2 = 4
    x[2048:2176] += rng.standard_normal(128) * 10.0  # window-aligned burst
    out = energy_op(Signal(samples=x, fs=1.0), nperseg=nperseg, noverlap=0,
                    pfa=1e-4)
    assert out["noise_var"] == pytest.approx(4.0, rel=0.15)
    assert out["detections"][2048 // nperseg]
