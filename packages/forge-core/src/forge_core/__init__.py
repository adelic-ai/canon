"""forge-core — an agnostic signal-analysis substrate.

No domain assumptions are baked in: cyber, EEG, and other domains live in
sibling packages or as consumers. See ~/canon/design/forge_core_step0_audit.md
and the forge-core-scoping memory for the five design decisions this package is
built on.
"""
from forge_core.signal import Signal, SignalKind
from forge_core.ops import Op, op, register, get, registered
from forge_core.lattice import (
    Scale,
    LatticeWalk,
    divisors,
    prime_factors,
    covers,
    hops_back_walk,
)
from forge_core.detection import (
    ca_cfar,
    os_cfar,
    ca_cfar_alpha,
    os_cfar_alpha,
)
from forge_core.energy import (
    energy_detector,
    energy_threshold,
    energy_pd,
)
from forge_core.spectral import Spectrum, welch_psd
from forge_core.changepoint import cusum, cusum_arl
from forge_core.goertzel import goertzel
from forge_core.filters import (
    butter_filter,
    notch_filter,
    band_power_bank,
    EEG_BANDS,
)
from forge_core.lock_in import lock_in
from forge_core.matched_filter import matched_filter
from forge_core.circular import (
    circular_mean,
    circular_variance,
    resultant_length,
)
from forge_core.verdict import (
    DetectionVerdict,
    WRecord,
    assemble_verdict,
)

__all__ = [
    "Signal",
    "SignalKind",
    "Op",
    "op",
    "register",
    "get",
    "registered",
    "Scale",
    "LatticeWalk",
    "divisors",
    "prime_factors",
    "covers",
    "hops_back_walk",
    "ca_cfar",
    "os_cfar",
    "ca_cfar_alpha",
    "os_cfar_alpha",
    "energy_detector",
    "energy_threshold",
    "energy_pd",
    "Spectrum",
    "welch_psd",
    "cusum",
    "cusum_arl",
    "goertzel",
    "butter_filter",
    "notch_filter",
    "band_power_bank",
    "EEG_BANDS",
    "lock_in",
    "matched_filter",
    "circular_mean",
    "circular_variance",
    "resultant_length",
    "DetectionVerdict",
    "WRecord",
    "assemble_verdict",
]
