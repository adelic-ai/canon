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
]
