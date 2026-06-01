"""Information-theoretic feature tests — Shannon entropy port fidelity + the windowed op.

Two layers: :func:`shannon_entropy` must match the textbook values it ports (a uniform
distribution over ``k`` symbols is ``log2(k)`` bits; a point mass is ``0``), and the
``windowed_entropy`` op must turn a categorical stream into a REAL entropy statistic that
*spikes* on a fan-out burst — the input shape a CFAR cell downstream is built to threshold.
"""

from __future__ import annotations

import numpy as np
import pytest

from forge_core.information import shannon_entropy, windowed_entropy
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
