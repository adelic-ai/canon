"""Matched-filter tests.

Cover white-noise template localisation (real + complex), the unit-H0-variance
SNR normalisation, and — the load-bearing correctness claim — that the colored-
noise prewhitener actually calibrates the detector: under correlated noise the
whitened statistic has unit variance while the naive (white) matched filter is
miscalibrated.
"""
import numpy as np
import pytest
from scipy.linalg import toeplitz
from scipy.signal import lfilter

from forge_core import matched_filter
from forge_core import ops
from forge_core.signal import Signal, SignalKind

mf_op = ops.get("matched_filter")


def _ar1(rho: float, n: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """An AR(1) noise realisation (unit process variance) and its L-lag covariance."""
    rng = np.random.default_rng(seed)
    sig_eps = np.sqrt(1.0 - rho**2)            # -> stationary variance 1
    noise = lfilter([sig_eps], [1.0, -rho], rng.standard_normal(n))
    return noise, rho  # rho returned so the caller builds R at its chosen L


def _ar1_cov(rho: float, L: int) -> np.ndarray:
    return toeplitz(rho ** np.arange(L))       # unit-variance AR(1) covariance


# ── registration ─────────────────────────────────────────────────────────────


def test_op_registered():
    assert "matched_filter" in ops.registered()
    assert isinstance(ops.get("matched_filter"), ops.Op)


# ── white-noise localisation ─────────────────────────────────────────────────


def test_locates_template_white():
    rng = np.random.default_rng(0)
    L, m, amp = 16, 1000, 5.0
    s = np.hanning(L)
    x = rng.standard_normal(4096)
    x[m : m + L] += amp * s                    # embed the template at offset m
    out = mf_op(Signal(samples=x, fs=1.0), template=s)
    assert out["peak_lag"] == m
    assert out["statistic"].size == 4096 - L + 1
    # normalised peak ~ amp * ||s||  (unit-variance noise)
    assert out["peak_value"] == pytest.approx(amp * np.linalg.norm(s), rel=0.2)


def test_locates_template_complex():
    rng = np.random.default_rng(1)
    L, m, amp = 24, 600, 4.0
    t = np.arange(L)
    s = np.exp(2j * np.pi * 0.1 * t)           # complex template
    x = (rng.standard_normal(2048) + 1j * rng.standard_normal(2048))
    x[m : m + L] += amp * s
    out = mf_op(Signal(samples=x, fs=1.0, kind=SignalKind.COMPLEX), template=s)
    assert out["peak_lag"] == m               # conjugation handled correctly
    assert np.abs(out["peak_value"]) == pytest.approx(amp * np.linalg.norm(s), rel=0.25)


def test_white_unit_h0_variance():
    rng = np.random.default_rng(2)
    s = np.hanning(32)
    x = rng.standard_normal(16384)            # noise only, unit variance
    out = mf_op(Signal(samples=x, fs=1.0), template=s)
    assert np.std(out["statistic"]) == pytest.approx(1.0, abs=0.1)


# ── colored-noise prewhitener (the correctness centerpiece) ──────────────────


def test_prewhitener_calibrates_under_colored_noise():
    rho, L = 0.9, 32
    noise, _ = _ar1(rho, 16384, seed=3)        # strongly correlated noise, var 1
    R = _ar1_cov(rho, L)
    s = np.hanning(L)
    sig = Signal(samples=noise, fs=1.0)

    whitened = mf_op(sig, template=s, noise_cov=R)
    naive = mf_op(sig, template=s)             # white assumption -> miscalibrated

    # The whitened detector has unit H0 variance; the naive one does not.
    assert np.std(whitened["statistic"]) == pytest.approx(1.0, abs=0.12)
    assert np.std(naive["statistic"]) > 1.3    # clearly miscalibrated for color
    assert whitened["whitened"] is True
    assert naive["whitened"] is False


def test_prewhitener_locates_template_in_colored_noise():
    rho, L, m, amp = 0.9, 32, 4000, 12.0
    noise, _ = _ar1(rho, 8192, seed=4)
    R = _ar1_cov(rho, L)
    s = np.hanning(L)
    x = noise.copy()
    x[m : m + L] += amp * s
    out = mf_op(Signal(samples=x, fs=1.0), template=s, noise_cov=R)
    assert out["peak_lag"] == m


# ── validation ────────────────────────────────────────────────────────────────


def test_rejects_template_longer_than_signal():
    s = np.ones(100)
    with pytest.raises(ValueError):
        mf_op(Signal(samples=np.ones(50), fs=1.0), template=s)


def test_rejects_non_pd_cov():
    s = np.ones(4)
    bad = -np.eye(4)                           # negative-definite
    with pytest.raises(ValueError):
        mf_op(Signal(samples=np.ones(64), fs=1.0), template=s, noise_cov=bad)


def test_rejects_wrong_cov_shape():
    s = np.ones(8)
    with pytest.raises(ValueError):
        mf_op(Signal(samples=np.ones(64), fs=1.0), template=s, noise_cov=np.eye(5))


def test_rejects_complex_with_noise_cov():
    s = np.ones(4)
    sig = Signal(samples=np.ones(64, dtype=complex), fs=1.0,
                 kind=SignalKind.COMPLEX)
    with pytest.raises(ValueError):
        mf_op(sig, template=s, noise_cov=np.eye(4))


def test_rejects_cyclic():
    s = np.ones(4)
    sig = Signal(samples=np.linspace(0, 6, 64), fs=1.0, kind=SignalKind.CYCLIC)
    with pytest.raises(TypeError):
        mf_op(sig, template=s)
