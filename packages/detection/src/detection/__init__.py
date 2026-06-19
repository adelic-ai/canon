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
    CLOUDTRAIL_ENUMERATION,
    CLOUDTRAIL_REGION_SWEEP,
    DISCOVERY_APIS,
    load_cloudtrail_events,
    load_discovery_events,
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
    lsass_dump_corroborated,
    ptt_signature,
    sigma_corroborator,
    spray_signature,
)
from detection.registry import REGISTRY, Detector, corpus_fields, run_applicable
from detection.killchain import build_model, forward_nexts
from detection.hmm import decode, emission_model, viterbi
from detection.orchestrator import TECH_TACTIC, orchestrate
from detection.cross_model import (
    cross_model_kerberoast,
    slice_entity_window,
    synthesize_kerberoast_corpus,
)
from detection.coverage_space import LocationCoverage, lsass_location_coverage
from detection.fidelity import attest_fidelity
from detection.adversarial import AdversarialCase, adversarial_corpus, attest_corpus
from detection.admission import (
    Neighbor,
    evaluate_against_neighbors,
    situate_d3fend,
    structural_relation,
)
from detection.baseline import blend_baselines, credibility_estimates, learn_entity_baseline
from detection.workspace import (
    Ruleset,
    Source,
    Workspace,
    diff_derived,
    load_derived,
    load_parameter,
    run_lsass_location_coverage,
    save_parameter,
    update_entity_baseline,
)
from detection.motif import (
    FieldMatch,
    MotifGraph,
    Suppression,
    attest_emitter_agreement,
    eval_python,
    eval_sparql,
    from_sigma,
    record_selector_provenance,
    to_rdf,
    to_sparql,
)
from detection.ingest import attest
from detection.render import render_dict, render_dot, render_report, report_from_dict, write_report
from detection.store import find_by_tag, load_verdict, render_stored, save_verdict
from detection.rarity import cloud_account_manipulation_verdicts, rare_actors
from detection.subgraph import (
    LSASS_DUMP,
    LSASS_READ_ANY,
    MotifSpec,
    PatternSpec,
    lsass_dump_verdicts,
    match_pattern,
    pattern_verdicts,
)
from detection.sigma_eval import block_matches, evaluability, evaluate_rule, is_evaluable, rule_fires
from detection.condition import condition_parses, eval_condition, parse_condition, rule_fires_general
from detection.audit import consume_sigma
from detection.sigma_panel import (
    corroborate,
    corroboration_coverage,
    coverage_category,
    gather,
    lsass_comsvcs_event,
    panel,
    signature,
)

__all__ = [
    # sigma corroboration — independent FCA/SKOS-deduped external confirmation of a canon finding
    "corroborate",
    "corroboration_coverage",   # per-detector coverage map (the honest spectrum, gaps recorded as data)
    "coverage_category",
    "panel",
    "gather",
    "signature",
    "lsass_comsvcs_event",
    # sigma evaluator — minimal faithful Sigma-subset matcher (the corroboration substrate)
    "rule_fires",
    "evaluate_rule",
    "block_matches",
    "is_evaluable",
    "evaluability",
    # condition — general boolean conditions over named blocks (all of/1 of/and/or/not) → firing code
    "parse_condition",
    "condition_parses",
    "eval_condition",
    "rule_fires_general",
    # audit — consume the Sigma corpus: classify (reasons=roadmap) + FCA-dedup → coverage scorecard
    "consume_sigma",
    # subgraph — structural multi-EID pattern detection (the structural paradigm; emits canonical verdicts)
    "MotifSpec",
    "PatternSpec",
    "match_pattern",
    "pattern_verdicts",
    "LSASS_DUMP",
    "LSASS_READ_ANY",
    "lsass_dump_verdicts",
    # ingest — attested signed-evidence boundary; emit's `evidence`+`attestation` earn custody off NONE
    "attest",
    # fidelity — a justified, reproducible claim about what a RULE covers (the warranted detects-edge)
    "attest_fidelity",
    # adversarial corpus — correct-by-construction cases stressing the semantics profile across emitters
    "AdversarialCase",
    "adversarial_corpus",
    "attest_corpus",
    # admission — evaluate a candidate detection's logic against neighbors (structural + fidelity + D3FEND)
    "Neighbor",
    "structural_relation",
    "evaluate_against_neighbors",
    "situate_d3fend",
    # motif IR — a detection as a molecule graph; two verified emitters (Python + SPARQL), agreement attested
    "FieldMatch",
    "Suppression",
    "MotifGraph",
    "from_sigma",
    "eval_python",
    "eval_sparql",
    "to_sparql",
    "to_rdf",
    "attest_emitter_agreement",
    "record_selector_provenance",
    # coverage-space — a verdict + the fidelity-attested detectors at its location (primary/witnesses/gaps)
    "lsass_location_coverage",
    "LocationCoverage",
    # workspace — the per-engagement case file the engine points at + writes back into (engine holds no data)
    "Workspace",
    "Source",
    "Ruleset",
    "run_lsass_location_coverage",
    "load_derived",
    "diff_derived",
    # workspace parameters store + per-entity credibility baseline (learned values accumulate in the workspace)
    "save_parameter",
    "load_parameter",
    "update_entity_baseline",
    "learn_entity_baseline",
    "blend_baselines",
    "credibility_estimates",
    # render — pure projection of a verdict + its provenance DAG into report / record / chart
    "render_dict",
    "render_report",
    "report_from_dict",
    "render_dot",
    "write_report",
    # store — persist a verdict (record + PROV-O graph + DOT), re-render later with no live Entity
    "save_verdict",
    "load_verdict",
    "render_stored",
    "find_by_tag",
    # rarity — flag the rare ACTOR for a sensitive action family (cred-access: rare doer, not breadth)
    "rare_actors",
    "cloud_account_manipulation_verdicts",
    # orchestrator — fire registry → map to tactic → project forward frontier from the learned model
    "orchestrate",
    "TECH_TACTIC",
    # kill-chain transition model — learned tactic→tactic search priors (the orchestrator's prior)
    "build_model",
    "forward_nexts",
    # HMM — emission model + Viterbi to infer the HIDDEN tactic path (disambiguates multi-tactic findings)
    "emission_model",
    "viterbi",
    "decode",
    # registry — enumerate proper's detectors + observability-gated dispatch (the orchestrator's seam)
    "Detector",
    "REGISTRY",
    "run_applicable",
    "corpus_fields",
    # cross-check (independent structural ∧ statistical → the cross_check axis, cross-paradigm)
    "cross_check_verdicts",
    "lsass_dump_corroborated",   # structural lsass-dump + Sigma corroboration recorded as a provenance edge
    "sigma_corroborator",        # the dependency-injected Sigma corroboration witness for pattern_verdicts
    # cross-model join — behavioral detector + tool-artifact rule corroborate at the entity+window grain
    "cross_model_kerberoast",
    "slice_entity_window",
    "synthesize_kerberoast_corpus",
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
    "CLOUDTRAIL_ENUMERATION",
    "DISCOVERY_APIS",
    "load_cloudtrail_events",
    "load_discovery_events",
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
