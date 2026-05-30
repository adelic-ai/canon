"""CFAR detection tests.

Cover the threshold-multiplier math (closed-form CA, numeric OS), the
window/edge geometry, the kind gate, and the headline behavioural claim from
the DSP borrow-list: OS-CFAR catches a second target that CA-CFAR misses when
the first target sits inside the reference window.
"""
import numpy as np
import pytest

from forge_core import ca_cfar_alpha, os_cfar_alpha
from forge_core.detection import _os_pfa
from forge_core import ops
from forge_core.signal import Signal, SignalKind

ca_cfar_op = ops.get("ca_cfar")
os_cfar_op = ops.get("os_cfar")


# ── multiplier math ──────────────────────────────────────────────────────────


def test_ca_alpha_matches_closed_form():
    n, pfa = 16, 1e-3
    assert ca_cfar_alpha(n, pfa) == pytest.approx(n * (pfa ** (-1.0 / n) - 1.0))


def test_ca_alpha_decreases_with_higher_pfa():
    assert ca_cfar_alpha(16, 1e-1) < ca_cfar_alpha(16, 1e-4)


def test_os_alpha_inverts_pfa():
    # Plugging the solved alpha back into the Pfa formula returns the target.
    for n, rank, pfa in [(16, 12, 1e-3), (24, 18, 1e-4), (8, 4, 1e-2)]:
        alpha = os_cfar_alpha(n, rank, pfa)
        assert _os_pfa(alpha, n, rank) == pytest.approx(pfa, rel=1e-6)


def test_alpha_input_validation():
    with pytest.raises(ValueError):
        ca_cfar_alpha(16, 1.0)
    with pytest.raises(ValueError):
        os_cfar_alpha(16, 20, 1e-3)  # rank > num_ref


# ── registration ─────────────────────────────────────────────────────────────


def test_ops_registered():
    assert "ca_cfar" in ops.registered()
    assert "os_cfar" in ops.registered()
    assert isinstance(ops.get("ca_cfar"), ops.Op)


# ── geometry & gate ──────────────────────────────────────────────────────────


def test_edge_region_is_no_decision():
    guard, train = 2, 8
    half = guard + train
    s = Signal(samples=np.ones(64), fs=1.0)
    out = ca_cfar_op(s, guard=guard, train=train).value()
    assert np.all(np.isnan(out["threshold"][:half]))
    assert np.all(np.isnan(out["threshold"][-half:]))
    assert not out["detections"][:half].any()
    assert not out["detections"][-half:].any()
    # interior cells have a finite threshold
    assert np.all(np.isfinite(out["threshold"][half:-half]))


def test_rejects_non_real():
    s = Signal(samples=np.ones(64, dtype=complex), fs=1.0, kind=SignalKind.COMPLEX)
    with pytest.raises(TypeError):
        ca_cfar_op(s)


def test_rejects_too_short():
    s = Signal(samples=np.ones(10), fs=1.0)
    with pytest.raises(ValueError):
        ca_cfar_op(s, guard=2, train=8).value()  # length checked in the kernel


# ── behaviour ─────────────────────────────────────────────────────────────────


def _noise_floor(n: int, seed: int = 0) -> np.ndarray:
    # Square-law statistic under H0 is exponentially distributed.
    return np.random.default_rng(seed).exponential(1.0, n)


def test_ca_detects_isolated_spike():
    x = _noise_floor(256)
    x[128] += 50.0  # a lone target well above the floor
    out = ca_cfar_op(Signal(samples=x, fs=1.0), guard=2, train=8, pfa=1e-4).value()
    assert out["detections"][128]
    # no spurious detections elsewhere at this low Pfa
    assert list(out["indices"]) == [128]


def test_os_beats_ca_under_interferer_masking():
    # A moderate target whose reference window holds several STRONGER
    # interferers. CA-CFAR's mean is inflated by the interferers and masks the
    # target; OS-CFAR's low-rank order statistic rejects the few high cells and
    # keeps the true floor, so it still detects.
    guard, train, pfa = 2, 8, 1e-4
    cut = 128
    x = _noise_floor(256)
    x[cut] += 40.0  # moderate target
    for k in (122, 124, 134):  # strong interferers inside cut's ref window
        x[k] += 150.0
    s = Signal(samples=x, fs=1.0)

    ca = ca_cfar_op(s, guard=guard, train=train, pfa=pfa).value()
    os = os_cfar_op(s, guard=guard, train=train, pfa=pfa).value()

    assert not ca["detections"][cut]  # masked by the interferers
    assert os["detections"][cut]      # interferers rejected, target survives
