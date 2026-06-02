"""detection — the orchestration layer above forge-core.

forge-core is the statistical spine (features, tests, FP control), domain-agnostic. This layer is
where **telemetry semantics** live: turning real events into candidate streams, choosing the grain,
dispatching forge-core's primitives, and (later) generating candidate pairs from the knowledge
layer. forge-core stays ignorant — it sees streams, windows, scores, p-values; this layer knows
what a source IP or an account is.

Two detector families validated on real labeled data:
- :mod:`detection.fanout` — ``entity → distribution over values`` (password spray, Kerberoasting):
  a *hard* anomaly, exact label match.
- :mod:`detection.offhours` — ``entity → distribution over time-of-day`` (circular statistics):
  a *soft* anomaly, partially labeled. Two binding shapes (``FanoutBinding`` / ``TemporalBinding``)
  now exist; a general ``Binding`` is extracted only if they force it.
"""
from detection.fanout import (
    PASSWORD_SPRAY,
    SERVICE_TICKET_FANOUT,
    FanoutBinding,
    FanoutCell,
    FanoutDetection,
    bucket_fanout,
    detect_fanout,
    fanout_entropy,
    fanout_verdict,
    fanout_verdicts,
    load_kerberos_events,
    run_binding,
)
from detection.offhours import (
    OFF_HOURS,
    OffHoursDetection,
    TemporalBinding,
    detect_offhours,
    offhours_verdict,
    offhours_verdicts,
    run_offhours,
)

__all__ = [
    # fan-out family (hard anomaly)
    "FanoutCell",
    "FanoutDetection",
    "FanoutBinding",
    "PASSWORD_SPRAY",
    "SERVICE_TICKET_FANOUT",
    "bucket_fanout",
    "fanout_entropy",
    "detect_fanout",
    "run_binding",
    "fanout_verdict",
    "fanout_verdicts",
    "load_kerberos_events",
    # temporal family (soft anomaly)
    "TemporalBinding",
    "OFF_HOURS",
    "OffHoursDetection",
    "detect_offhours",
    "run_offhours",
    "offhours_verdict",
    "offhours_verdicts",
]
