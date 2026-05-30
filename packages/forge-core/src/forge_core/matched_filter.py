"""Matched filter — the optimal known-template detector.

The matched filter is the provably maximum-SNR linear detector for a signal of
*known shape* in additive noise (North 1943). It is the top rung of the
detection ladder: energy detector (signal unknown) -> Goertzel / lock-in
(frequency known) -> matched filter (full shape known). The detector statistic
is the cross-correlation of the data with the template; the peak marks where the
template best aligns, and its height is the matched-filter SNR.

White noise. The optimal filter is the template itself: the statistic is
``corr[j] = sum_k x[j+k] * conj(s[k])`` (``scipy.signal.correlate`` already
conjugates the template, so a complex template is handled correctly). Normalised
by ``sqrt(noise_var) * ||s||`` the statistic has unit variance under H0, so its
value is directly a per-lag SNR and is threshold-/CFAR-feedable.

Colored noise. The bare correlation is optimal only in *white* noise; with
correlated background the template must be **prewhitened**. The colored-noise
matched filter is ``h = R^{-1} s`` where ``R`` is the noise covariance, and the
statistic ``x^T R^{-1} s`` is realised as ``correlate(x, h)``. ``R = L L^T``
(Cholesky) is solved via ``scipy.linalg.cho_solve``; normalising by
``sqrt(s^T R^{-1} s)`` again gives unit H0 variance. This is the prewhitener the
borrow-list flags as the second half of the matched-filter build.

Wraps ``scipy.signal.correlate`` (FFT method) and ``scipy.linalg`` Cholesky.
"""
from __future__ import annotations

from typing import Any

import numpy as np
from scipy.linalg import cho_factor, cho_solve
from scipy.signal import correlate

from forge_core.ops import op
from forge_core.signal import Signal, SignalKind


@op(
    "matched_filter",
    accepts=(SignalKind.REAL, SignalKind.COMPLEX),
    inputs=("template", "noise_cov"),
)
def matched_filter(
    signal: Signal,
    template: np.ndarray,
    noise_cov: np.ndarray | None = None,
    *,
    noise_var: float = 1.0,
    **_: Any,
) -> dict[str, Any]:
    """Matched-filter detection of a known ``template`` over a REAL/COMPLEX signal.

    Parameters
    ----------
    template:
        The known waveform to detect, 1-D, length ``L <= signal length``.
    noise_cov:
        Optional ``L x L`` noise covariance for the colored-noise prewhitener
        (``h = R^{-1} s``). Must be symmetric positive-definite. When ``None``
        the white-noise matched filter (the template itself) is used.
        Prewhitening is REAL-only; combining ``noise_cov`` with a COMPLEX signal
        raises.
    noise_var:
        Noise variance for the white-noise normalisation (default 1.0). Ignored
        when ``noise_cov`` is given (the scale is carried by ``R``).

    Returns
    -------
    dict with keys ``statistic`` (unit-H0-variance correlation series, ``valid``
    mode), ``lags`` (window start index per output sample), ``peak_lag``,
    ``peak_value``, ``template_len``, and ``whitened`` (bool).
    """
    x = signal.require(SignalKind.REAL, SignalKind.COMPLEX).samples
    s = np.asarray(template)
    if s.ndim != 1:
        raise ValueError(f"template must be 1-D, got {s.ndim}-D")
    if s.size < 1 or s.size > x.size:
        raise ValueError(
            f"template length ({s.size}) must be in [1, {x.size}]"
        )
    if noise_var <= 0:
        raise ValueError(f"noise_var must be > 0, got {noise_var}")

    whitened = noise_cov is not None
    if whitened:
        if signal.is_complex:
            raise ValueError("colored-noise prewhitening is REAL-only")
        R = np.asarray(noise_cov, dtype=np.float64)
        if R.shape != (s.size, s.size):
            raise ValueError(
                f"noise_cov must be {(s.size, s.size)}, got {R.shape}"
            )
        try:
            cfac = cho_factor(R)  # raises LinAlgError if not positive-definite
        except np.linalg.LinAlgError as e:
            raise ValueError("noise_cov must be positive-definite") from e
        h = cho_solve(cfac, s)
        norm = float(np.sqrt(s @ h))  # sqrt(s^T R^-1 s)
    else:
        h = s
        norm = float(np.sqrt(noise_var) * np.linalg.norm(s))

    corr = correlate(x, h, mode="valid", method="fft") / norm
    lags = np.arange(corr.size)  # 'valid': output j == template start at index j
    peak_idx = int(np.argmax(np.abs(corr)))

    return {
        "statistic": corr,
        "lags": lags,
        "peak_lag": int(lags[peak_idx]),
        "peak_value": corr[peak_idx],
        "template_len": int(s.size),
        "whitened": whitened,
    }
