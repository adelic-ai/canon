"""Lock-in detection tests.

The headline claim: recover a tone's amplitude and phase even when the noise
power dwarfs the signal. Also cover off-frequency rejection, time localisation,
the REAL gate, and validation.
"""
import numpy as np
import pytest

from forge_core import lock_in
from forge_core import ops
from forge_core.signal import Signal, SignalKind

lock_in_op = ops.get("lock_in")


def _central(a: np.ndarray) -> np.ndarray:
    """Drop filtfilt edge transients — keep the central half."""
    n = a.size
    return a[n // 4 : 3 * n // 4]


# ── registration ─────────────────────────────────────────────────────────────


def test_op_registered():
    assert "lock_in" in ops.registered()
    assert isinstance(ops.get("lock_in"), ops.Op)


# ── recovery below the noise floor ───────────────────────────────────────────


def test_recovers_amplitude_buried_in_noise():
    fs, f0, n, amp = 1000.0, 50.0, 8192, 1.0
    rng = np.random.default_rng(0)
    t = np.arange(n) / fs
    # noise std 3 >> signal amplitude 1: the tone is invisible in the raw trace
    x = amp * np.cos(2 * np.pi * f0 * t) + 3.0 * rng.standard_normal(n)
    out = lock_in_op(Signal(samples=x, fs=fs), freq=f0, bandwidth=2.0).value()
    recovered = np.median(_central(out["amplitude"]))
    assert recovered == pytest.approx(amp, abs=0.3)


def test_recovers_phase():
    fs, f0, n, phi = 1000.0, 50.0, 8192, 0.7
    rng = np.random.default_rng(1)
    t = np.arange(n) / fs
    x = np.cos(2 * np.pi * f0 * t + phi) + 1.0 * rng.standard_normal(n)
    out = lock_in_op(Signal(samples=x, fs=fs), freq=f0, bandwidth=2.0).value()
    # phase is a CYCLIC Signal now; take its angle samples for the median.
    assert np.median(_central(out["phase"].samples)) == pytest.approx(phi, abs=0.2)


def test_off_frequency_rejected():
    fs, f0, n = 1000.0, 50.0, 8192
    t = np.arange(n) / fs
    x = np.cos(2 * np.pi * f0 * t)  # tone only at 50 Hz
    on = np.median(_central(lock_in_op(Signal(samples=x, fs=fs), freq=f0,
                                       bandwidth=2.0).value()["amplitude"]))
    off = np.median(_central(lock_in_op(Signal(samples=x, fs=fs), freq=200.0,
                                        bandwidth=2.0).value()["amplitude"]))
    assert off < 0.05 * on


# ── time localisation ────────────────────────────────────────────────────────


def test_amplitude_localises_tone_in_time():
    fs, f0, n = 1000.0, 50.0, 12000
    t = np.arange(n) / fs
    x = np.zeros(n)
    x[4000:8000] = np.cos(2 * np.pi * f0 * t[4000:8000])  # tone only in the middle
    out = lock_in_op(Signal(samples=x, fs=fs), freq=f0, bandwidth=5.0).value()
    amp = out["amplitude"]
    assert np.median(amp[5000:7000]) > 10 * np.median(amp[500:2000])


def test_outputs_have_signal_length():
    fs, n = 1000.0, 4096
    out = lock_in_op(Signal(samples=np.cos(2 * np.pi * 50 * np.arange(n) / fs),
                            fs=fs), freq=50.0, bandwidth=2.0).value()
    assert out["demod"].shape == out["amplitude"].shape == (n,)
    assert out["phase"].samples.shape == (n,)
    assert out["phase"].is_cyclic  # phase is a CYCLIC Signal
    assert np.iscomplexobj(out["demod"])


# ── gate & validation ─────────────────────────────────────────────────────────


def test_rejects_non_real():
    s = Signal(samples=np.ones(1024, dtype=complex), fs=1000.0,
               kind=SignalKind.COMPLEX)
    with pytest.raises(TypeError):
        lock_in_op(s, freq=50.0, bandwidth=2.0)


def test_validates_freq_and_bandwidth():
    s = Signal(samples=np.cos(2 * np.pi * 50 * np.arange(2048) / 1000.0),
               fs=1000.0)
    with pytest.raises(ValueError):
        lock_in_op(s, freq=600.0, bandwidth=2.0).value()   # > Nyquist
    with pytest.raises(ValueError):
        lock_in_op(s, freq=50.0, bandwidth=0.0).value()    # bandwidth must be > 0
