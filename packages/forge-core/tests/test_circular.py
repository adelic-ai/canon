"""Circular-statistics tests.

Cover the headline correctness claim (circular mean is right at the wrap boundary
where the arithmetic mean is wrong), the period passthrough (non-2π circles),
the concentration/dispersion limits of the resultant length, the
variance/resultant complement contract, and the CYCLIC kind gate (REAL/COMPLEX
rejected, empty rejected) — the PASS/XFAIL pairing the substrate uses as its
self-falsifying test form.
"""
import numpy as np
import pytest

from forge_core import circular_mean, circular_variance, resultant_length
from forge_core.signal import Signal, SignalKind


def _cyclic(samples, period=2.0 * np.pi) -> Signal:
    return Signal(samples=samples, fs=1.0, kind=SignalKind.CYCLIC, period=period)


def _circ_dist(a: float, b: float, period: float) -> float:
    """Shortest angular distance between ``a`` and ``b`` on a circle of ``period``."""
    d = abs(a - b) % period
    return min(d, period - d)


# ── headline: branch-cut correctness ─────────────────────────────────────────


def test_circular_mean_correct_across_branch_cut():
    # Two angles a hair either side of 0; their true mean is 0, not π.
    samples = [0.1, 2.0 * np.pi - 0.1]
    s = _cyclic(samples)
    # The arithmetic mean is diametrically wrong — establishes the test matters.
    assert float(np.mean(samples)) == pytest.approx(np.pi, abs=1e-6)
    # The circular mean is 0 (≡ 2π); compare on the circle.
    assert _circ_dist(circular_mean(s), 0.0, 2.0 * np.pi) < 1e-9


def test_circular_mean_period_passthrough():
    # Degrees mod 360: mean of 350° and 10° is 0°/360°, not 180°.
    s = _cyclic([350.0, 10.0], period=360.0)
    assert _circ_dist(circular_mean(s), 0.0, 360.0) < 1e-6


# ── concentration / dispersion limits ────────────────────────────────────────


def test_resultant_length_concentrated_is_one():
    s = _cyclic([1.234, 1.234, 1.234])
    assert resultant_length(s) == pytest.approx(1.0, abs=1e-12)
    assert circular_variance(s) == pytest.approx(0.0, abs=1e-12)


def test_resultant_length_antipodal_is_zero():
    s = _cyclic([0.0, np.pi])
    assert resultant_length(s) == pytest.approx(0.0, abs=1e-12)
    assert circular_variance(s) == pytest.approx(1.0, abs=1e-12)


def test_variance_and_resultant_are_complements():
    rng = np.random.default_rng(0)
    s = _cyclic(rng.uniform(0.0, 2.0 * np.pi, 200))
    assert circular_variance(s) + resultant_length(s) == pytest.approx(1.0)


# ── kind gate (negatives must fail) ──────────────────────────────────────────


def test_rejects_real():
    s = Signal(samples=np.ones(8), fs=1.0, kind=SignalKind.REAL)
    for fn in (circular_mean, circular_variance, resultant_length):
        with pytest.raises(TypeError):
            fn(s)


def test_rejects_complex():
    s = Signal(samples=np.ones(8, dtype=complex), fs=1.0, kind=SignalKind.COMPLEX)
    for fn in (circular_mean, circular_variance, resultant_length):
        with pytest.raises(TypeError):
            fn(s)


def test_rejects_empty():
    s = _cyclic([])
    for fn in (circular_mean, circular_variance, resultant_length):
        with pytest.raises(ValueError):
            fn(s)
