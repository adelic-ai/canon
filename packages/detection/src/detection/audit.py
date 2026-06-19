"""Sigma consumption pass — compile + FCA/SKOS-dedup the whole corpus; the audit/scorecard falls out.

Not a read-only audit: this is the act of CONSUMING Sigma through the mechanism (run in Python, the reference
runtime). It walks every rule, classifies create-ability via :func:`~detection.sigma_eval.evaluability` (the
reason histogram = the IR-breadth roadmap: which construct blocks the most rules), and for the evaluable rules
runs the **FCA dedup** — the signature ``(logsource, field-set keyed on)`` is the FCA attribute-set; rules
sharing it are one detection *concept* = one equivalence class. So the report is the consumption result:

* raw rule count and **% that compiles to firing code**,
* **distinct detection classes** after FCA dedup (and how many raw rules collapsed = redundancy),
* **why the rest don't compile**, ranked (the roadmap),
* **ATT&CK technique coverage** — techniques with ≥1 evaluable rule vs honest NONE gaps.

No LLM. The create/classify + dedup axes need no labeled data; fidelity (does it actually catch attacks) is the
separate, label-bounded axis the dataset-generator feeds.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from detection.fidelity import _cid
from detection.sigma_eval import evaluability
from detection.sigma_panel import SIGMA, signature

_ATTACK = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _techniques(rule: dict) -> set[str]:
    out: set[str] = set()
    for t in rule.get("tags") or []:
        m = _ATTACK.search(str(t))
        if m:
            out.add(m.group(1).upper())
    return out


def _logsource_key(rule: dict) -> str:
    ls = rule.get("logsource")
    if not isinstance(ls, dict):
        return "unknown"
    return f"{ls.get('product', '?')}/{ls.get('category', ls.get('service', '?'))}"


def consume_sigma(root: Path = SIGMA) -> dict:
    """Consume the Sigma corpus under ``root`` and return the consumption report (content-addressed). See the
    module docstring for the fields. ``redundancy.collapsed`` = evaluable rules that FCA-merged into an
    existing class; ``techniques_gap`` = techniques that appear in some rule but have NO evaluable rule (the
    honest create-level coverage gap)."""
    total = 0
    reasons: Counter = Counter()
    logsources: Counter = Counter()
    tech_all: set[str] = set()
    tech_evaluable: set[str] = set()
    classes: dict = defaultdict(list)          # FCA signature -> [rule ids]  (evaluable only)
    evaluable = 0

    for p in Path(root).rglob("*.yml"):
        total += 1
        try:
            r = yaml.safe_load(p.read_text())
        except Exception:
            reasons["unparseable"] += 1
            continue
        if not isinstance(r, dict):
            reasons["not-a-rule"] += 1
            continue
        ok, reason = evaluability(r)
        reasons[reason] += 1
        techs = _techniques(r)
        tech_all |= techs
        logsources[_logsource_key(r)] += 1
        if ok:
            evaluable += 1
            tech_evaluable |= techs
            classes[signature(r)].append(r.get("id", p.name))

    distinct = len(classes)
    body = {
        "total": total,
        "evaluable": evaluable,
        "distinct_detections": distinct,                        # after FCA dedup
        "reasons": dict(reasons),
        "techniques_total": len(tech_all),
        "techniques_evaluable": len(tech_evaluable),
    }
    return {
        **body,
        "evaluable_pct": round(100 * evaluable / total, 1) if total else 0.0,
        "redundancy": {"collapsed": evaluable - distinct,
                       "ratio": round(evaluable / distinct, 2) if distinct else 0.0},
        "techniques_gap": sorted(tech_all - tech_evaluable),
        "logsources_top": dict(logsources.most_common(15)),
        # the IR-breadth roadmap: non-ok reasons ranked by how many rules they block
        "ir_roadmap": [[k, v] for k, v in reasons.most_common() if k != "ok"],
        "cid": _cid(body),
    }
