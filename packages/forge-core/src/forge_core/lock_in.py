"""Lock-in (synchronous) detection — pull a known tone below the noise floor.

A lock-in amplifier extracts a sinusoid of *known* frequency from noise that may
dwarf it, by coherent integration. Mix the signal with a complex reference at
the carrier frequency and low-pass the product: the component at the carrier
collapses to DC (a complex amplitude carrying the in-phase and quadrature parts)
while everything else is pushed away and filtered out. The low-pass bandwidth
sets the integration time, and hence how far below the broadband noise floor a
tone can be recovered — a narrower bandwidth integrates longer and rejects more
noise.

For a real input ``x = A*cos(2*pi*f0*t + phi)``, mixing with ``exp(-j*2*pi*f0*t)``
gives ``(A/2)*exp(j*phi)`` at DC plus an image at ``2*f0`` that the low-pass
removes. So the demodulated DC term recovers amplitude ``A = 2*|demod|`` and
phase ``phi = angle(demod)``. Choose ``bandwidth`` well below ``f0`` (and below
``2*f0``) so the carrier is isolated from its image.

Lock-in is the *coherent* counterpart of the energy detector: where the energy
detector (radiometer) integrates power non-coherently with no phase knowledge,
lock-in integrates coherently at a known frequency and so reaches far deeper
into noise — at the cost of needing that frequency. It sits alongside Goertzel
on the known-frequency rung; Goertzel gives a per-window power, lock-in gives a
continuous complex envelope (amplitude + phase) and localises *when* the tone is
present.

Composes existing forge-core ops: complex mixing here, then the zero-phase
Butterworth low-pass from :mod:`forge_core.filters`.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from forge_core.filters import butter_filter
from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


@op("lock_in", accepts=(SignalKind.REAL,))
def lock_in(
    signal: Signal,
    *,
    freq: float,
    bandwidth: float,
    order: int = 4,
    **_: Any,
) -> dict[str, Any]:
    """Lock-in detection of a tone at ``freq`` over a REAL signal.

    Parameters
    ----------
    freq:
        Carrier frequency to lock onto, in Hz (``0 < freq < fs/2``).
    bandwidth:
        Low-pass cutoff in Hz applied to the mixed signal. Sets the integration
        time / noise rejection; choose well below ``freq``.
    order:
        Order of the Butterworth low-pass. Default 4.

    Returns
    -------
    dict with keys ``frequency``, ``bandwidth``, ``demod`` (complex envelope
    ``I + jQ`` per sample), ``amplitude`` (``2*|demod|``, recovered ``A``), and
    ``phase`` (``angle(demod)``). The amplitude series rises where the tone is
    present, so it localises in time and is CFAR-feedable.
    """
    x = signal.require(SignalKind.REAL).samples
    nyq = signal.fs / 2.0
    if not 0.0 < freq < nyq:
        raise ValueError(f"freq ({freq}) must be in (0, {nyq})")
    if not 0.0 < bandwidth < nyq:
        raise ValueError(f"bandwidth ({bandwidth}) must be in (0, {nyq})")

    reference = np.exp(-2j * np.pi * freq * signal.times)
    mixed = Signal(
        samples=x * reference,
        fs=signal.fs,
        kind=SignalKind.COMPLEX,
        t0=signal.t0,
        meta=signal.meta,
    )
    # Coherent integration = zero-phase low-pass of the mixed product. Call the
    # pure butter kernel (.fn), not the op: this is eager intra-op composition,
    # not a separate lineage node.
    demod = butter_filter.fn(
        mixed, cutoff=bandwidth, btype="lowpass", order=order, zero_phase=True
    ).samples

    return {
        "frequency": float(freq),
        "bandwidth": float(bandwidth),
        "demod": demod,
        "amplitude": 2.0 * np.abs(demod),
        # Phase is angular data: a CYCLIC Signal (period 2π), so downstream
        # circular_mean/variance see correct wrap semantics instead of laundering
        # angles through linear stats at the ±π branch cut.
        "phase": Signal(
            samples=np.angle(demod),
            fs=signal.fs,
            kind=SignalKind.CYCLIC,
            t0=signal.t0,
        ),
    }
