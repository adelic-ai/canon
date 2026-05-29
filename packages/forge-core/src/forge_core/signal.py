"""Signal container — the atom forge-core operates on.

A Signal is a 1-D sequence plus the sampling metadata needed to interpret it,
gated by a ``SignalKind``: Real, Complex, or Cyclic. The kind is the contract
operations consult to dispatch correctly — e.g. the mean of a Cyclic signal is
the circular mean, not the arithmetic one.

This is the forge-core port of forge.core.signal with the Real/Complex/Cyclic
type gate added (design decision #3). The dataclass shape (samples, fs, t0,
meta) is preserved from forge.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

import numpy as np


class SignalKind(Enum):
    """The interpretation contract for a signal's samples.

    REAL
        Ordinary real-valued samples (float64).
    COMPLEX
        Complex samples (complex128) — analytic signals, FFT outputs, IQ data.
    CYCLIC
        Angular/phase samples (float64) living on a circle of circumference
        ``period``. Arithmetic that assumes a flat line (mean, difference) must
        be done circularly; consult ``kind`` before operating.
    """

    REAL = "real"
    COMPLEX = "complex"
    CYCLIC = "cyclic"


_DTYPE = {
    SignalKind.REAL: np.float64,
    SignalKind.COMPLEX: np.complex128,
    SignalKind.CYCLIC: np.float64,
}


@dataclass(frozen=True, slots=True)
class Signal:
    """An immutable 1-D signal with sampling metadata and a kind gate.

    Attributes
    ----------
    samples:
        1-D array. Dtype is coerced to match ``kind`` (float64 for REAL/CYCLIC,
        complex128 for COMPLEX).
    fs:
        Sampling frequency in Hz. Must be > 0.
    kind:
        The interpretation contract. Defaults to REAL.
    t0:
        Timestamp (seconds) of the first sample. Defaults to 0.0.
    period:
        For CYCLIC signals, the circumference of the circle the samples live on
        (default 2π). Ignored for REAL/COMPLEX.
    meta:
        Free-form metadata dict (units, provenance, channel name, …).
    """

    samples: np.ndarray
    fs: float
    kind: SignalKind = SignalKind.REAL
    t0: float = 0.0
    period: float = 2.0 * np.pi
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        arr = np.asarray(self.samples, dtype=_DTYPE[self.kind])
        if arr.ndim != 1:
            raise ValueError(f"Signal must be 1-D, got {arr.ndim}-D")
        if self.fs <= 0:
            raise ValueError(f"fs must be > 0, got {self.fs}")
        if self.kind is SignalKind.CYCLIC and self.period <= 0:
            raise ValueError(f"cyclic period must be > 0, got {self.period}")
        object.__setattr__(self, "samples", arr)

    @property
    def n(self) -> int:
        return self.samples.shape[0]

    @property
    def duration(self) -> float:
        """Length in seconds."""
        return self.n / self.fs

    @property
    def times(self) -> np.ndarray:
        """Sample timestamps in seconds."""
        return self.t0 + np.arange(self.n) / self.fs

    @property
    def is_real(self) -> bool:
        return self.kind is SignalKind.REAL

    @property
    def is_complex(self) -> bool:
        return self.kind is SignalKind.COMPLEX

    @property
    def is_cyclic(self) -> bool:
        return self.kind is SignalKind.CYCLIC

    def with_samples(self, samples: np.ndarray) -> "Signal":
        """Return a copy with new samples, same metadata and kind."""
        return replace(self, samples=samples)

    def require(self, *kinds: SignalKind) -> "Signal":
        """Assert this signal is one of ``kinds``; return self for chaining.

        The type gate in action: an Op that only makes sense on REAL data calls
        ``signal.require(SignalKind.REAL)`` at its entry.
        """
        if self.kind not in kinds:
            allowed = ", ".join(k.name for k in kinds)
            raise TypeError(
                f"operation requires signal kind in {{{allowed}}}, "
                f"got {self.kind.name}"
            )
        return self

    def __len__(self) -> int:
        return self.n
