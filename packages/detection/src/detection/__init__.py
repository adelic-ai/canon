"""detection — the orchestration layer above forge-core.

forge-core is the statistical spine (features, tests, FP control), domain-agnostic. This layer is
where **telemetry semantics** live: turning real events into candidate streams, choosing the grain,
dispatching forge-core's primitives, and (later) generating candidate pairs from the knowledge
layer. forge-core stays ignorant — it sees streams, windows, scores, p-values; this layer knows
what a source IP or an account is.

Three detector families now:
- :mod:`detection.fanout` — ``entity → distribution over values`` (password spray, Kerberoasting;
  also the AWS CloudTrail region-sweep, a third binding in a new domain): a *hard* anomaly, exact
  label match on real labeled telemetry.
- :mod:`detection.offhours` — ``entity → distribution over time-of-day`` (circular statistics):
  a *soft* anomaly, partially labeled.
- :mod:`detection.coordination` — ``two entity streams → their dependence`` (mutual information;
  synchronized multi-host beaconing): a *constructive existence-proof* on a synthetic mechanism-
  modelled corpus (MI beats the marginals), **not** field-validated.

Three binding shapes now exist (``FanoutBinding`` / ``TemporalBinding`` / ``CoordinationBinding`` —
the last is the *two-stream* shape the others said to wait for). The "wait for a 3rd family" gate on a
general ``Binding`` is therefore met — but generalization stays *deliberately unforced*: extract it
only if the three shapes actually rhyme (concrete-first), not because a counter hit three.
"""
from detection.cloudtrail import (
    CLOUDTRAIL_REGION_SWEEP,
    load_cloudtrail_events,
)
from detection.coordination import (
    BEACON_COORDINATION,
    CoordinationBinding,
    CoordinationDetection,
    coordination_verdict,
    coordination_verdicts,
    detect_coordination,
    host_activity_vectors,
    host_marginal_features,
    synthesize_coordination_events,
)
from detection.fanout import (
    PASSWORD_SPRAY,
    SERVICE_TICKET_FANOUT,
    FanoutBinding,
    FanoutCell,
    FanoutDetection,
    bucket_fanout,
    detect_by_distinct_count,
    detect_fanout,
    distinct_value_counts,
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
from detection.cross_check import (
    cross_check_verdicts,
    kerberoast_signature,
    load_kerberos_rows,
    ptt_signature,
    spray_signature,
)
from detection.registry import REGISTRY, Detector, corpus_fields, run_applicable
from detection.killchain import build_model, forward_nexts
from detection.orchestrator import TECH_TACTIC, orchestrate

__all__ = [
    # orchestrator — fire registry → map to tactic → project forward frontier from the learned model
    "orchestrate",
    "TECH_TACTIC",
    # kill-chain transition model — learned tactic→tactic search priors (the orchestrator's prior)
    "build_model",
    "forward_nexts",
    # registry — enumerate proper's detectors + observability-gated dispatch (the orchestrator's seam)
    "Detector",
    "REGISTRY",
    "run_applicable",
    "corpus_fields",
    # cross-check (independent structural ∧ statistical → the cross_check axis, cross-paradigm)
    "cross_check_verdicts",
    "kerberoast_signature",
    "ptt_signature",
    "spray_signature",
    "load_kerberos_rows",
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
    "distinct_value_counts",
    "detect_by_distinct_count",
    # fan-out, third binding — a new telemetry domain (AWS CloudTrail) for the same detector
    "CLOUDTRAIL_REGION_SWEEP",
    "load_cloudtrail_events",
    # coordination family (third detector family — MI over entity PAIRS; constructive existence-proof)
    "CoordinationBinding",
    "CoordinationDetection",
    "BEACON_COORDINATION",
    "synthesize_coordination_events",
    "host_activity_vectors",
    "host_marginal_features",
    "detect_coordination",
    "coordination_verdict",
    "coordination_verdicts",
    # temporal family (soft anomaly)
    "TemporalBinding",
    "OFF_HOURS",
    "OffHoursDetection",
    "detect_offhours",
    "run_offhours",
    "offhours_verdict",
    "offhours_verdicts",
]
