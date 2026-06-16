"""Sigma corroboration panel — independent, FCA/SKOS-deduped external confirmation of a canon finding.

A canon cell confirms a milestone from the relational graph. This panel asks a *separate* question:
do INDEPENDENT, community-authored detections agree? A canon verdict corroborated by external rules is
more defensible than canon's word alone.

You cannot just count rules. T1003.001 carries dozens of tagged Sigma rules, many near-duplicates (same
logsource, same fields, different tool string). Counting all of them as independent confirmations is
false corroboration. So the panel DEDUPS first, by formal-concept structure:

  FCA  — objects = rules, attributes = (logsource, the set of fields keyed on). Rules sharing an
         attribute-set are the same detection concept → one equivalence class → ONE vote. The ⊆ order on
         field-sets is the concept lattice.
  SKOS — that subsumption is broader/narrower: a rule keying on ``{TargetImage}`` alone is BROADER than
         one also keying on ``{GrantedAccess, CallTrace}`` (the superset is the narrower concept).

Honest coverage (the completeness channel, applied to the panel itself): a class whose representative
rule needs operators the minimal evaluator (:mod:`detection.sigma_eval`) doesn't implement is reported
NOT-EVALUATED — counted toward neither corroboration nor contradiction.

Belnap: the panel emits TRUE (≥1 deduped class fires) or NONE (nothing evaluable, or evaluated-but-none-
fired). It structurally never emits FALSE — a Sigma rule not firing is a coverage gap in that rule, not
evidence the attack is absent. Non-firing cannot refute; it can only fail to corroborate.

Data: ``packages/semantic-cyber/data/sigma-rules/`` (real SigmaHQ corpus).
"""

from __future__ import annotations

import collections
from pathlib import Path

import yaml

from provenance import NONE, TRUE, Four

from detection.sigma_eval import is_evaluable, rule_fires

SIGMA = Path(__file__).parents[4] / "packages/semantic-cyber/data/sigma-rules"


def gather(technique: str, *, root: Path = SIGMA) -> list[tuple[Path, dict]]:
    """All rules tagged ``attack.<technique>`` with a parseable detection + logsource."""
    tag = f"attack.{technique.lower()}"
    rules = []
    for p in root.rglob("*.yml"):
        try:
            txt = p.read_text()
            if tag not in txt.lower():
                continue
            r = yaml.safe_load(txt)
        except Exception:
            continue
        if (isinstance(r, dict) and isinstance(r.get("detection"), dict)
                and isinstance(r.get("logsource"), dict)):
            rules.append((p, r))
    return rules


def _logsource(r: dict) -> tuple:
    ls = r["logsource"]
    return (ls.get("category"), ls.get("product"), ls.get("service"))


def _fields(block) -> frozenset:
    return frozenset(k.split("|")[0] for k in block) if isinstance(block, dict) else frozenset()


def signature(r: dict) -> tuple:
    """The detection signature = (logsource, field-set keyed on) — the FCA attribute-set."""
    return (_logsource(r), _fields(r["detection"].get("selection")))


def panel(technique: str, event: dict, category: str, *, root: Path = SIGMA) -> dict:
    """Run the deduped panel for ``technique`` against ``event`` over rules of logsource ``category``.
    Returns ``{tagged, relevant, classes, evaluated, fired, skipped}``."""
    rules = gather(technique, root=root)
    relevant = [(p, r) for p, r in rules if _logsource(r)[0] == category]

    classes: dict[tuple, list] = collections.defaultdict(list)
    for p, r in relevant:
        classes[signature(r)].append((p, r))

    fired, evaluated, skipped = [], 0, []
    for sig, members in classes.items():
        rep_p, rep_r = members[0]                   # one representative per class = one vote
        if not is_evaluable(rep_r):
            skipped.append((sig, len(members)))
            continue
        evaluated += 1
        if rule_fires(rep_r, event):
            fired.append((rep_p.name, sorted(sig[1]), len(members)))
    return {"tagged": len(rules), "relevant": len(relevant), "classes": len(classes),
            "evaluated": evaluated, "fired": fired, "skipped": skipped}


def corroborate(technique: str, event: dict, category: str = "process_access",
                *, root: Path = SIGMA) -> dict:
    """Belnap-style corroboration of a canon finding by the deduped external panel. Adds ``votes``,
    ``belnap`` (TRUE | NONE — never FALSE), and a human ``verdict`` to the :func:`panel` result."""
    res = panel(technique, event, category, root=root)
    votes = len(res["fired"])
    if votes > 0:
        belnap, verdict = TRUE, f"CORROBORATED-true ({votes} independent deduped vote(s))"
    elif res["evaluated"] == 0:
        belnap, verdict = NONE, "NONE (no class evaluable here — panel abstains, doesn't contradict)"
    else:
        belnap, verdict = NONE, "UNCORROBORATED (panel evaluated but none fired — canon-only finding)"
    return {**res, "votes": votes, "belnap": belnap, "verdict": verdict}


def lsass_comsvcs_event(events: list[dict]) -> dict | None:
    """The ground-truth T1003.001 event canon's ``lsass_dump_subgraph`` fires on (the comsvcs EID10),
    reconstructed from a Sysmon corpus — the demo/test target for corroborating that finding."""
    spawn = next((e for e in events if str(e.get("EventID")) == "1"
                  and "comsvcs" in str(e.get("CommandLine", "")).lower()), None)
    if not spawn:
        return None
    return next((e for e in events if str(e.get("EventID")) == "10"
                 and e.get("SourceProcessGUID") == spawn.get("ProcessGuid")
                 and "lsass" in str(e.get("TargetImage", "")).lower()), None)
