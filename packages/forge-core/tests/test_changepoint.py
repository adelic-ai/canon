"""CUSUM sequential change-detection tests.

Cover the Siegmund ARL approximation, registration, the REAL gate, the robust
target/sigma estimation, and the headline behaviour: detect an upward and a
downward mean shift with the right direction and no pre-change alarm; and the
reset flag's effect on multi-change detection.
"""
import numpy as np
import pytest

from forge_core import cusum, cusum_arl
from forge_core import ops
from forge_core.signal import Signal, SignalKind

cusum_op = ops.get("cusum")


# ── ARL sizing ───────────────────────────────────────────────────────────────


def test_arl_in_control_far_exceeds_out_of_control():
    k, h = 0.5, 5.0
    assert cusum_arl(k, h, delta=0.0) > 100 * cusum_arl(k, h, delta=2.0)


def test_arl_decreases_with_larger_shift():
    k, h = 0.5, 5.0
    assert cusum_arl(k, h, 1.0) > cusum_arl(k, h, 2.0) > cusum_arl(k, h, 3.0)


def test_arl_zero_drift_limit():
    # delta == k -> drift 0 -> (h + 1.166)**2
    h = 5.0
    assert cusum_arl(0.5, h, delta=0.5) == pytest.approx((h + 1.166) ** 2)


def test_arl_validation():
    with pytest.raises(ValueError):
        cusum_arl(-1.0, 5.0)
    with pytest.raises(ValueError):
        cusum_arl(0.5, 0.0)


# ── registration & gate ──────────────────────────────────────────────────────


def test_op_registered():
    assert "cusum" in ops.registered()
    assert isinstance(ops.get("cusum"), ops.Op)


def test_rejects_non_real():
    s = Signal(samples=np.ones(64, dtype=complex), fs=1.0, kind=SignalKind.COMPLEX)
    with pytest.raises(TypeError):
        cusum_op(s)


def test_validates_params():
    s = Signal(samples=np.zeros(64), fs=1.0)
    with pytest.raises(ValueError):
        cusum_op(s, h=0.0).value()
    with pytest.raises(ValueError):
        cusum_op(s, k=-1.0).value()


# ── behaviour ─────────────────────────────────────────────────────────────────


def test_detects_upward_shift():
    rng = np.random.default_rng(0)
    x = np.concatenate([rng.standard_normal(200),
                        rng.standard_normal(200) + 2.0])  # +2 sigma shift at 200
    out = cusum_op(Signal(samples=x, fs=1.0), target=0.0, sigma=1.0, k=0.5, h=5.0).value()
    post = out["indices"][out["indices"] >= 200]
    assert post.size > 0
    assert post[0] < 215               # detected within a few samples of the shift
    assert out["direction"][post[0]] == 1


def test_detects_downward_shift_direction():
    rng = np.random.default_rng(1)
    x = np.concatenate([rng.standard_normal(200),
                        rng.standard_normal(200) - 2.0])
    out = cusum_op(Signal(samples=x, fs=1.0), target=0.0, sigma=1.0).value()
    first = out["indices"][0]
    assert out["direction"][first] == -1


def test_reset_detects_both_directions():
    rng = np.random.default_rng(2)
    # excursion above the reference, then below it -> upper then lower alarms
    x = np.concatenate([rng.standard_normal(150),
                        rng.standard_normal(150) + 3.0,
                        rng.standard_normal(150) - 3.0])
    s = Signal(samples=x, fs=1.0)
    out = cusum_op(s, target=0.0, sigma=1.0, reset=True).value()
    assert out["upper"].any()
    assert out["lower"].any()
    # the first lower alarm comes after the first upper alarm
    assert np.flatnonzero(out["lower"])[0] > np.flatnonzero(out["upper"])[0]


def test_robust_estimation_recovers_scale():
    rng = np.random.default_rng(3)
    x = rng.standard_normal(2000) * 3.0 + 5.0  # mu=5, sigma=3, in control
    out = cusum_op(Signal(samples=x, fs=1.0)).value()  # no target/sigma given
    assert out["target"] == pytest.approx(5.0, abs=0.3)
    assert out["sigma"] == pytest.approx(3.0, rel=0.1)
