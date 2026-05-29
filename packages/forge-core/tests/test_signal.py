import numpy as np
import pytest

from forge_core.signal import Signal, SignalKind


def test_real_signal_basics():
    s = Signal(samples=[1, 2, 3, 4], fs=2.0)
    assert s.kind is SignalKind.REAL
    assert s.n == 4
    assert s.samples.dtype == np.float64
    assert s.duration == 2.0
    np.testing.assert_allclose(s.times, [0.0, 0.5, 1.0, 1.5])
    assert len(s) == 4


def test_complex_kind_coerces_dtype():
    s = Signal(samples=[1 + 2j, 3 - 1j], fs=1.0, kind=SignalKind.COMPLEX)
    assert s.is_complex
    assert s.samples.dtype == np.complex128


def test_cyclic_default_period_is_two_pi():
    s = Signal(samples=[0.0, np.pi], fs=1.0, kind=SignalKind.CYCLIC)
    assert s.is_cyclic
    assert s.period == pytest.approx(2 * np.pi)


def test_cyclic_period_must_be_positive():
    with pytest.raises(ValueError):
        Signal(samples=[0.0], fs=1.0, kind=SignalKind.CYCLIC, period=0.0)


def test_fs_must_be_positive():
    with pytest.raises(ValueError):
        Signal(samples=[1.0], fs=0.0)


def test_rejects_non_1d():
    with pytest.raises(ValueError):
        Signal(samples=[[1, 2], [3, 4]], fs=1.0)


def test_immutable():
    s = Signal(samples=[1.0, 2.0], fs=1.0)
    with pytest.raises(Exception):
        s.fs = 5.0  # type: ignore[misc]


def test_with_samples_preserves_kind_and_meta():
    s = Signal(samples=[1 + 0j], fs=3.0, kind=SignalKind.COMPLEX, meta={"u": "v"})
    s2 = s.with_samples([2 + 0j, 3 + 0j])
    assert s2.kind is SignalKind.COMPLEX
    assert s2.fs == 3.0
    assert s2.meta == {"u": "v"}
    assert s2.n == 2


def test_require_passes_and_chains():
    s = Signal(samples=[1.0], fs=1.0)
    assert s.require(SignalKind.REAL) is s
    assert s.require(SignalKind.REAL, SignalKind.CYCLIC) is s


def test_require_rejects_wrong_kind():
    s = Signal(samples=[1.0], fs=1.0)
    with pytest.raises(TypeError):
        s.require(SignalKind.COMPLEX)
