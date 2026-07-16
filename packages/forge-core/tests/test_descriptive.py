"""Descriptive Axis-A features — cardinality (distinct-count) and concentration (HHI). They read
the same per-window category histogram as windowed_entropy and agree with it on a fan-out spike."""

import numpy as np
import pytest

from forge_core.descriptive import (
    distinct_count,
    herfindahl,
    windowed_distinct,
    windowed_herfindahl,
)
from forge_core.signal import Signal, SignalKind


def _codes(arr):
    return Signal(np.asarray(arr, dtype=np.float64), fs=1.0, kind=SignalKind.REAL)


def _fanout(window):
    """single-symbol baseline → one window of `window` distinct symbols → baseline."""
    return np.concatenate([
        np.zeros(window * 2, dtype=float),
        np.arange(window, dtype=float),
        np.zeros(window * 2, dtype=float),
    ])


# ── scalar contracts ─────────────────────────────────────────────────────────
def test_distinct_count():
    assert distinct_count(np.array([0, 0, 1, 2, 2])) == 3
    assert distinct_count(np.array([])) == 0
    assert distinct_count(np.array([5, 5, 5])) == 1


def test_herfindahl_one_symbol_is_max():
    assert herfindahl(np.array([10.0])) == pytest.approx(1.0)
    assert herfindahl(np.array([1, 1, 1, 1])) == pytest.approx(0.25)  # uniform over 4 → 1/4
    assert herfindahl(np.array([0, 0])) == 0.0


def test_herfindahl_is_entropys_mass_mirror():
    assert herfindahl(np.array([100, 1, 1])) > herfindahl(np.array([1, 1, 1]))


# ── windowed ops ─────────────────────────────────────────────────────────────
def test_windowed_distinct_spikes_on_fanout():
    W = 16
    out = windowed_distinct(_codes(_fanout(W)), window=W, step=W).value().samples
    assert out.max() == W
    assert int((out == W).sum()) == 1  # exactly one fan-out window
    assert out.min() == 1              # baseline windows are a single symbol


def test_windowed_herfindahl_dips_on_fanout():
    W = 16
    out = windowed_herfindahl(_codes(_fanout(W)), window=W, step=W).value().samples
    assert out.min() == pytest.approx(1.0 / W)  # uniform fan-out window → 1/k
    assert out.max() == pytest.approx(1.0)      # single-symbol baseline → 1


def test_distinct_hhi_entropy_agree_on_the_fanout_window():
    """One event, three lenses: at the fan-out window distinct peaks, HHI bottoms, entropy peaks."""
    from forge_core.information import windowed_entropy

    W = 16
    sig = _codes(_fanout(W))
    d = windowed_distinct(sig, window=W, step=W).value().samples
    h = windowed_herfindahl(sig, window=W, step=W).value().samples
    e = windowed_entropy(sig, window=W, step=W).value().samples
    i = int(d.argmax())
    assert d[i] == W
    assert h[i] == pytest.approx(1.0 / W)
    assert e[i] == pytest.approx(np.log2(W))


# ── contracts: kind gate + guards ────────────────────────────────────────────
def test_window_too_long_raises():
    with pytest.raises(ValueError):
        windowed_distinct(_codes(np.arange(4.0)), window=8).value()


def test_rejects_non_real_signalkind():
    sig = Signal(np.zeros(32, dtype=np.complex128), fs=1.0, kind=SignalKind.COMPLEX)
    with pytest.raises(Exception):
        windowed_distinct(sig, window=8, step=8).value()
