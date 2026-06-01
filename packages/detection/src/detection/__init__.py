"""detection — the orchestration layer above forge-core.

forge-core is the statistical spine (features, tests, FP control), domain-agnostic. This layer is
where **telemetry semantics** live: turning real events into candidate streams, choosing the grain,
dispatching forge-core's primitives, and (later) generating candidate pairs from the knowledge
layer. forge-core stays ignorant — it sees streams, windows, scores, p-values; this layer knows
what a source IP or an account is.

First slice: :mod:`detection.fanout` — Kerberos password-spray as account fan-out, the concrete
vertical that the binding abstraction is meant to *emerge from*, not be designed ahead of.
"""
from detection.fanout import (
    FanoutCell,
    bucket_fanout,
    detect_fanout,
    fanout_entropy,
    load_kerberos_events,
)

__all__ = [
    "FanoutCell",
    "bucket_fanout",
    "fanout_entropy",
    "detect_fanout",
    "load_kerberos_events",
]
