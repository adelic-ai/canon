"""Information-theoretic feature tests — Shannon entropy port fidelity + the windowed op.

Two layers: :func:`shannon_entropy` must match the textbook values it ports (a uniform
distribution over ``k`` symbols is ``log2(k)`` bits; a point mass is ``0``), and the
``windowed_entropy`` op must turn a categorical stream into a REAL entropy statistic that
*spikes* on a fan-out burst — the input shape a CFAR cell downstream is built to threshold.
"""

from __future__ import annotations

import numpy as np
import pytest

from forge_core.information import (
    kl_divergence,
    shannon_entropy,
    windowed_entropy,
    windowed_kl,
)
from forge_core.signal import Signal, SignalKind
from provenance import Entity


# ── shannon_entropy: port fidelity ───────────────────────────────────────────


def test_point_mass_is_zero_entropy():
    assert shannon_entropy([7]) == 0.0
    assert shannon_entropy([0, 5, 0]) == 0.0  # one symbol, the rest never occur


def test_uniform_over_k_is_log2_k():
    for k in (2, 4, 8, 16):
        assert shannon_entropy(np.ones(k)) == pytest.approx(np.log2(k))


def test_empty_or_zero_total_is_zero():
    assert shannon_entropy([]) == 0.0
    assert shannon_entropy([0, 0, 0]) == 0.0


def test_entropy_is_relabel_invariant():
    # H depends on the distribution of counts, not which symbol carries which count.
    assert shannon_entropy([3, 1, 4, 1]) == pytest.approx(shannon_entropy([1, 4, 1, 3]))


# ── windowed_entropy op ───────────────────────────────────────────────────────


def _codes_signal(codes, fs=1.0):
    return Signal(np.asarray(codes, dtype=np.float64), fs=fs, kind=SignalKind.REAL)


def test_windowed_entropy_returns_lazy_entity_producing_a_real_signal():
    sig = windowed_entropy(_codes_signal([0, 0, 1, 1, 2, 2]), window=2, step=2)
    assert isinstance(sig, Entity)  # lazy: an op call builds a DAG node, not a value
    out = sig.value()
    assert isinstance(out, Signal) and out.kind is SignalKind.REAL
    # three non-overlapping windows, each two identical codes → entropy 0 each.
    np.testing.assert_allclose(out.samples, [0.0, 0.0, 0.0])


def test_window_of_all_distinct_codes_is_log2_window():
    # A window of `window` distinct labels is uniform over `window` symbols → log2(window) bits.
    sig = windowed_entropy(_codes_signal(list(range(8))), window=8, step=1)
    np.testing.assert_allclose(sig.value().samples, [np.log2(8)])


def test_entropy_spikes_on_a_fanout_burst():
    # Baseline: a single repeated code → entropy ~0. Burst: a run of distinct codes → high entropy.
    base = [0] * 20
    burst = list(range(16))  # 16 distinct labels
    codes = base + burst + [0] * 20
    out = windowed_entropy(_codes_signal(codes), window=16, step=1).value().samples
    # Somewhere the window sits entirely on the burst → entropy == log2(16) == 4 bits;
    # the all-baseline windows are 0. The series spikes.
    assert out.max() == pytest.approx(4.0)
    assert out.min() == pytest.approx(0.0)


def test_output_fs_is_decimated_by_step():
    sig = windowed_entropy(_codes_signal(list(range(20)), fs=10.0), window=4, step=5)
    assert sig.value().fs == pytest.approx(2.0)  # 10 / step


def test_stream_shorter_than_window_raises():
    with pytest.raises(ValueError, match="too short"):
        windowed_entropy(_codes_signal([0, 1, 2]), window=8).value()


def test_rejects_non_real_kind_at_build_time():
    cyclic = Signal(np.zeros(8), fs=1.0, kind=SignalKind.CYCLIC)
    with pytest.raises(TypeError, match="windowed_entropy"):
        windowed_entropy(cyclic, window=4)


# ── kl_divergence: port fidelity ──────────────────────────────────────────────


def test_identical_distributions_have_zero_kl():
    assert kl_divergence([3, 1, 4], [3, 1, 4]) == pytest.approx(0.0)
    assert kl_divergence([3, 1, 4], [6, 2, 8]) == pytest.approx(0.0)  # same after normalizing


def test_kl_is_asymmetric_and_positive():
    # A non-mirror pair (mirror pairs like [8,1,1]/[1,1,8] are coincidentally symmetric).
    d_pq = kl_divergence([10, 1], [1, 1])
    d_qp = kl_divergence([1, 1], [10, 1])
    assert d_pq > 0 and d_qp > 0
    assert d_pq != pytest.approx(d_qp)  # not symmetric


def test_kl_known_value_two_symbols():
    # P=(1,0), Q=(1/2,1/2): D = 1·log2(1 / 0.5) = 1 bit. (Q has no zero where P is positive.)
    assert kl_divergence([1, 0], [1, 1]) == pytest.approx(1.0)


def test_kl_disjoint_support_is_inf():
    assert kl_divergence([1, 0], [0, 1]) == float("inf")


# ── windowed_kl op: the binning decision made explicit ────────────────────────


def test_windowed_kl_zero_when_window_matches_baseline():
    # baseline uniform over 4 symbols; a window that is also uniform → KL ~ 0 (up to smoothing).
    codes = _codes_signal([0, 1, 2, 3, 0, 1, 2, 3])
    out = windowed_kl(codes, baseline=np.ones(4), window=4, step=4, smoothing=0.5).value().samples
    assert np.all(out < 0.2)  # near zero; smoothing keeps it from being exactly 0


def test_windowed_kl_spikes_on_a_distributional_break():
    # baseline concentrated on symbol 0; a window that shifts onto rare symbols → large finite KL.
    baseline = np.array([100.0, 1.0, 1.0, 1.0])  # symbol 0 dominates the normal profile
    normal_win = [0, 0, 0, 0]
    break_win = [3, 3, 3, 3]  # all mass on a symbol the baseline barely saw
    out_normal = windowed_kl(_codes_signal(normal_win), baseline=baseline, window=4, smoothing=0.5).value().samples
    out_break = windowed_kl(_codes_signal(break_win), baseline=baseline, window=4, smoothing=0.5).value().samples
    assert out_break[0] > out_normal[0]
    assert np.isfinite(out_break[0])  # novelty is finite (smoothed), not inf or dropped


def test_windowed_kl_rejects_codes_outside_the_declared_alphabet():
    # baseline length 3 → alphabet {0,1,2}; a code of 5 is out of the declared support.
    with pytest.raises(ValueError, match="declared alphabet"):
        windowed_kl(_codes_signal([0, 1, 5, 2]), baseline=np.ones(3), window=4).value()


def test_windowed_kl_smoothing_must_be_positive():
    with pytest.raises(ValueError, match="smoothing must be > 0"):
        windowed_kl(_codes_signal([0, 1, 2, 3]), baseline=np.ones(4), window=4, smoothing=0.0).value()


def test_windowed_kl_calibration_is_a_used_edge():
    from provenance import lineage

    det = windowed_kl(_codes_signal([0, 1, 2, 3]), baseline=np.ones(4), window=4)
    assert isinstance(det, Entity)
    assert len(lineage(det)) >= 3  # the kl node + the code source + the baseline source
