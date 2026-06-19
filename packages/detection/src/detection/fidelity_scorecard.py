"""Fidelity scorecard — the fidelity axis of consuming Sigma: of the rules that COMPILE, which actually
CATCH the labeled attack instances of their technique.

The consumption pass (``audit.consume_sigma``) measures the **create** axis — what compiles to firing code
(~99% of Sigma). This measures the **fidelity** axis — does a compiled rule fire on real labeled ground truth.
"Claims technique T" (the rule's `attack.t…` tag) is an assertion; *catching a labeled instance of T* is the
warranted fact. The two diverge sharply: a rule tagged T1003.001 typically catches only its *specific* LSASS-
dump variant, not the comsvcs instance — so most rules are honestly **silent** on any one instance.

Label-bounded by construction: fidelity is measurable only where we have labeled positives (a few real corpora
+ the synthetic generators). Techniques without labels are fidelity-**NONE** (unknown), never a faked pass —
that gap is exactly what the dataset-generator exists to fill. Built on :func:`detection.fidelity.attest_fidelity`.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from detection.fidelity import _cid, attest_fidelity
from detection.sigma_eval import is_evaluable
from detection.sigma_panel import SIGMA, gather


def technique_fidelity(technique: str, positives: list[dict], *, corpus_id: str, corpus_cid: str,
                       sigma_root: Path = SIGMA) -> dict:
    """For one labeled technique: run **every evaluable Sigma rule claiming it** on the labeled ``positives``
    (via :func:`attest_fidelity`) and tally — how many actually catch the instances vs are silent, with each
    rule's Belnap coverage + miss cause. ``catch_rate`` = catching / evaluable."""
    rules = [(p, r) for p, r in gather(technique, root=sigma_root) if is_evaluable(r)]
    atts = []
    for p, r in rules:
        a = attest_fidelity(r, positives, technique, rule_bytes=p.read_bytes(),
                            corpus_id=corpus_id, corpus_cid=corpus_cid)
        atts.append({"rule": p.name, "coverage": a["coverage"], "cause": a.get("cause", {}).get("kind")})
    catching = [a for a in atts if a["coverage"] in ("true", "both")]
    silent = [a for a in atts if a["coverage"] == "false"]
    silent_causes = Counter(a["cause"] for a in silent)
    # rules whose telemetry channel THIS corpus actually exercises (exclude wrong-channel misses) — the fair
    # denominator: don't penalise a file_event rule for not firing on a process_access campaign.
    applicable = len(rules) - silent_causes.get("missing-telemetry", 0)
    return {
        "technique": technique,
        "rules_evaluable": len(rules),
        "rules_catching": len(catching),       # actually fire on ≥1 labeled instance (warranted)
        "rules_silent": len(silent),           # claim the technique but miss every instance here
        "rules_applicable": applicable,        # evaluable minus wrong-channel (missing-telemetry) rules
        "catch_rate": round(len(catching) / len(rules), 3) if rules else 0.0,
        "catch_rate_applicable": round(len(catching) / applicable, 3) if applicable else 0.0,
        "silent_causes": dict(silent_causes),  # missing-telemetry (wrong channel) vs logic-gap vs allowlist
        "attestations": atts,
    }


def fidelity_scorecard(cases: list[dict]) -> dict:
    """Run :func:`technique_fidelity` over each labeled case (``{technique, positives, corpus_id, corpus_cid}``)
    and aggregate. Honest about scope: only the cases' techniques are measured; every other technique is
    fidelity-NONE until labeled."""
    per = {c["technique"]: technique_fidelity(c["technique"], c["positives"],
                                              corpus_id=c["corpus_id"], corpus_cid=c["corpus_cid"])
           for c in cases}
    body = {t: {"rules_evaluable": v["rules_evaluable"], "rules_catching": v["rules_catching"]}
            for t, v in per.items()}
    return {
        "techniques_tested": sorted(per),
        "per_technique": per,
        "note": ("fidelity measured ONLY for techniques with labeled ground truth; all others are NONE "
                 "(unknown) until labeled — the dataset-generator's job. 'claims technique' ≠ 'catches it'."),
        "cid": _cid(body),
    }


def grounded_fidelity(technique: str, scenarios, background: list[dict], *, sigma_root: Path = SIGMA) -> dict:
    """Two-sided fidelity over a GROUNDED corpus (synthetic attacks injected into a real benign background):
    **recall** (rules catching the injected malicious events) AND **false positives** (rules firing on the
    benign background). The real background is what turns one-sided catch-rate into precision + recall; a
    ``clean_catcher`` catches the attack AND stays silent on the benign population.

    Honest caveat: over a real corpus, the FP count is an UPPER BOUND — the "benign" background may contain
    unlabeled real activity (e.g. OTRF's own campaign), so a counted false-positive may be a true detection of
    something we didn't label. Use a clean/synthetic background for exact FP semantics."""
    from synthcyber import grounded_scenario_corpus

    from detection.sigma_eval import evaluate_rule, is_evaluable

    corpus = grounded_scenario_corpus(scenarios, background)
    malicious = [e for e, lab in zip(corpus["events"], corpus["labels"]) if lab]
    benign = [e for e, lab in zip(corpus["events"], corpus["labels"]) if not lab]
    rules = [(p, r) for p, r in gather(technique, root=sigma_root) if is_evaluable(r)]

    rows = []
    for p, r in rules:
        catches = any(evaluate_rule(r, e)["fires"] for e in malicious)
        fps = sum(1 for e in benign if evaluate_rule(r, e)["fires"])
        rows.append({"rule": p.name, "catches": catches, "false_positives": fps})

    catching = [x for x in rows if x["catches"]]
    return {
        "technique": technique,
        "n_malicious": len(malicious),
        "n_benign": len(benign),
        "rules_evaluable": len(rules),
        "rules_catching": len(catching),                                       # recall side
        "rules_with_false_positives": len([x for x in rows if x["false_positives"] > 0]),  # precision side
        "clean_catchers": sorted(x["rule"] for x in catching if x["false_positives"] == 0),  # catch + no FP
        "rows": rows,
        "cid": _cid({"technique": technique, "n_malicious": len(malicious), "n_benign": len(benign),
                     "rows": sorted((x["rule"], x["catches"], x["false_positives"]) for x in rows)}),
    }


def otrf_lsass_t1003_case(path: str) -> dict:
    """The one solid real-data labeled case on hand: the comsvcs T1003.001 instance in an OTRF LSASS corpus
    (selected by the recorded `_comsvcs_positive` selector)."""
    from detection.coverage_space import _comsvcs_positive
    from detection.subgraph import load_sysmon_events
    pos = _comsvcs_positive(load_sysmon_events(path))
    return {"technique": "T1003.001", "positives": [pos] if pos else [],
            "corpus_id": "OTRF/LSASS_campaign_03", "corpus_cid": "cid:sha256:otrf"}
