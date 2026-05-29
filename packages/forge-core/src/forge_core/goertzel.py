"""Goertzel — single-frequency power, the known-frequency detector.

The Goertzel algorithm (Goertzel 1958) evaluates one DFT term by a second-order
recurrence instead of a full FFT: when you already know the frequency of
interest, it costs O(N) per frequency with no transform and no O(N log N)
overhead. It is the *known-frequency* rung of the detection ladder — between the
energy detector (frequency unknown) and the matched filter (full shape known) —
and is effectively a matched filter for a single complex sinusoid.

For a target frequency ``f`` at sampling rate ``fs``, set ``omega = 2*pi*f/fs``
and run, over each block of ``M`` samples,

    s[n] = x[n] + 2*cos(omega)*s[n-1] - s[n-2]

then form the (generalised) DFT coefficient ``y = s[M-1] - exp(-j*omega)*s[M-2]``;
the detector statistic is ``|y|**2``. This is the *generalised* Goertzel — the
recurrence is exact for any ``omega`` (the target need not land on an FFT bin).
At an integer bin ``omega = 2*pi*k/M`` it reproduces ``|X[k]|**2`` exactly.

Under white noise the per-bin power is chi2(2)-distributed (exponential), so the
``power`` series this op emits is exactly the REAL, non-negative statistic the
CFAR layer thresholds adaptively, or that an energy/chi2 threshold gates — use
the sliding form to localise a known-frequency beacon in time, then hand
``power`` to ``ca_cfar``/``os_cfar``.

Pure numpy; the recurrence is vectorised across sliding windows.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


@op("goertzel")
def goertzel(
    signal: Signal,
    *,
    freq: float,
    nperseg: int | None = None,
    noverlap: int | None = None,
    return_complex: bool = False,
    **_: Any,
) -> dict[str, Any]:
    """Goertzel single-frequency power over a REAL or COMPLEX signal.

    Parameters
    ----------
    freq:
        Target frequency in Hz. Must satisfy ``|freq| <= fs/2`` (Nyquist).
    nperseg:
        Block length. ``None`` (default) uses the whole signal as one block.
    noverlap:
        Samples of overlap between consecutive windows; defaults to
        ``nperseg // 2`` when sliding. The window step is ``nperseg - noverlap``.
    return_complex:
        If True, also return the complex DFT coefficient ``coeff`` per window
        (magnitude is the detector; phase is available for downstream use).

    Returns
    -------
    dict with keys ``frequency``, ``window_starts`` (sample index of each
    window), ``power`` (``|y|**2`` per window, shape ``(n_windows,)``),
    ``nperseg``, ``noverlap``, and ``coeff`` (complex, only if
    ``return_complex``).
    """
    x = signal.require(SignalKind.REAL, SignalKind.COMPLEX).samples
    n = x.size
    if abs(freq) > signal.fs / 2:
        raise ValueError(
            f"|freq| ({abs(freq)}) exceeds Nyquist ({signal.fs / 2})"
        )
    if nperseg is None:
        nperseg = n
    if nperseg < 1:
        raise ValueError(f"nperseg must be >= 1, got {nperseg}")
    if nperseg > n:
        raise ValueError(f"nperseg ({nperseg}) exceeds signal length ({n})")
    if noverlap is None:
        noverlap = nperseg // 2
    if not 0 <= noverlap < nperseg:
        raise ValueError(f"noverlap must be in [0, {nperseg}), got {noverlap}")
    step = nperseg - noverlap

    windows = np.lib.stride_tricks.sliding_window_view(x, nperseg)[::step]
    window_starts = np.arange(0, n - nperseg + 1, step)

    omega = 2.0 * np.pi * freq / signal.fs
    coeff = 2.0 * np.cos(omega)
    # Second-order recurrence, vectorised across all windows at once.
    s_prev = np.zeros(windows.shape[0], dtype=windows.dtype)
    s_prev2 = np.zeros(windows.shape[0], dtype=windows.dtype)
    for t in range(nperseg):
        s = windows[:, t] + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    y = s_prev - np.exp(-1j * omega) * s_prev2
    power = np.abs(y) ** 2

    result: dict[str, Any] = {
        "frequency": float(freq),
        "window_starts": window_starts,
        "power": power,
        "nperseg": nperseg,
        "noverlap": noverlap,
    }
    if return_complex:
        result["coeff"] = y
    return result
