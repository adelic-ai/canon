"""Sigma consumption pass — compile + FCA/SKOS-dedup the whole corpus; the audit/scorecard falls out.

Not a read-only audit: this is the act of CONSUMING Sigma through the mechanism (run in Python, the reference
runtime). It walks every rule, classifies create-ability via :func:`~detection.sigma_eval.evaluability` (the
reason histogram = the IR-breadth roadmap: which construct blocks the most rules), and for the evaluable rules
runs dedup under **two concept keys that BRACKET redundancy** (neither measures it):

* field-set ``signature`` ``(logsource, fields keyed on)`` — value-BLIND, so it OVER-collapses (value-distinct
  detections sharing a field-set merge) → the **upper bound** on redundancy;
* value-aware ``content_signature`` ``(logsource, content_digest)`` — collapses only byte-identical content
  (≈none in a curated corpus) → the **lower bound** (≈1.0×).

True redundancy (rules that *catch* the same instances) is between the two and needs the catch-set — no
structural key reaches it. So the report is the consumption result:

* raw rule count and **% that compiles to firing code**,
* **distinct detection classes** under each key (``distinct_detections`` field-set / ``..._content``), with
  ``redundancy`` (upper bound) and ``redundancy_content`` (lower bound),
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
from detection.sigma_panel import SIGMA, content_signature, signature

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
    classes: dict = defaultdict(list)          # field-set FCA signature -> [rule ids]  (evaluable only)
    content_classes: dict = defaultdict(list)  # value-aware content signature -> [rule ids]
    evaluable = 0

    for p in Path(root).rglob("*.yml"):
        total += 1
        try:
            r = yaml.safe_load(p.read_text())
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
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
            rid = r.get("id", p.name)
            classes[signature(r)].append(rid)
            try:
                content_classes[content_signature(r)].append(rid)
            except (ValueError, KeyError, TypeError, AttributeError):
                content_classes[("uncompilable", rid)].append(rid)   # never silently merge an outlier

    distinct = len(classes)
    distinct_content = len(content_classes)
    body = {
        "total": total,
        "evaluable": evaluable,
        "distinct_detections": distinct,                        # field-set dedup → redundancy UPPER bound
        "distinct_detections_content": distinct_content,        # exact-content dedup → redundancy LOWER bound
        "reasons": dict(reasons),
        "techniques_total": len(tech_all),
        "techniques_evaluable": len(tech_evaluable),
    }
    return {
        **body,
        "evaluable_pct": round(100 * evaluable / total, 1) if total else 0.0,
        # The two keys BRACKET true redundancy, neither measures it. Field-set OVER-collapses (value-blind:
        # value-distinct detections sharing a field-set merge) → an UPPER bound. Exact-content collapses only
        # byte-identical rules (≈none in a curated corpus) → a LOWER bound ≈1.0x. True redundancy (rules that
        # CATCH the same instances) is between, and needs the catch-set — no structural key reaches it.
        "redundancy": {"collapsed": evaluable - distinct,
                       "ratio": round(evaluable / distinct, 2) if distinct else 0.0,
                       "basis": "field-set — over-collapse-biased UPPER bound"},
        "redundancy_content": {"collapsed": evaluable - distinct_content,
                               "ratio": round(evaluable / distinct_content, 2) if distinct_content else 0.0,
                               "basis": "exact-content — duplicate-only LOWER bound (truth needs catch-set)"},
        "techniques_gap": sorted(tech_all - tech_evaluable),
        "logsources_top": dict(logsources.most_common(15)),
        # the IR-breadth roadmap: non-ok reasons ranked by how many rules they block
        "ir_roadmap": [[k, v] for k, v in reasons.most_common() if k != "ok"],
        "cid": _cid(body),
    }
