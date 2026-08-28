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

Generalized beyond the first (process_access) cell: rules are selected by a ``logsource`` selector that
is a bare category string *or* a category/product/service subset (e.g. ``{"product": "aws", "service":
"cloudtrail"}`` for cloud detectors). And the panel scores a *set* of events (a class fires if its
representative fires on ANY of them) — entity-level corroboration, for detectors that flag an entity over
a distribution (fan-out / rarity) rather than a single structural event. Honest spectrum on the real
corpus: T1003.001 and T1580 corroborate (a community class fires); T1098 evaluates but is UNCORROBORATED
(SigmaHQ's account-manipulation rules cover different IAM ops than our family); T1558.003 has same-
logsource rules but a field-name impedance (raw-Windows vs Splunk-CIM) — a mapping layer, deferred.

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
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
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
    """The detection signature = (logsource, field-set keyed on) — the FCA attribute-set.

    Value-BLIND, so it OVER-COLLAPSES: rules reading the same fields with different values fold into one
    concept (32 distinct macOS detections → 1). Use :func:`content_signature` for the value-aware key; this
    one is retained for the field-set FCA lattice view only."""
    return (_logsource(r), _fields(r["detection"].get("selection")))


def content_signature(r: dict, ir=None) -> tuple:
    """Value-AWARE concept key — ``(logsource, content_digest of the compiled IR)``. The over-collapse fix
    for :func:`signature`: two rules sharing a field-set but matching different VALUES get DISTINCT keys (the
    32-macOS-rules→1 collapse becomes 32→32), so dedup/whittling keys on *what a rule matches*, not merely
    *which fields it reads*. Pass a precompiled ``ir`` to skip recompiling (the round already has it). Still
    blind to semantic equivalence between differently-structured rules — only the catch-set closes that."""
    from detection.rule_ir import compile_rule
    if ir is None:
        ir = compile_rule(r)
    return (_logsource(r), ir.content_digest())


def _ls_match(r: dict, sel: dict) -> bool:
    """Does rule ``r``'s logsource match every key given in ``sel`` (a subset of category/product/
    service)? Empty ``sel`` matches all."""
    cat, prod, svc = _logsource(r)
    got = {"category": cat, "product": prod, "service": svc}
    return all(got.get(k) == v for k, v in sel.items())


def _as_selector(logsource) -> dict:
    """A ``logsource`` arg is either a bare category string (back-compat) or a subset dict of
    category/product/service (e.g. ``{"product": "aws", "service": "cloudtrail"}``)."""
    return {"category": logsource} if isinstance(logsource, str) else dict(logsource)


def panel(technique: str, events, logsource="process_access", *, root: Path = SIGMA) -> dict:
    """Run the deduped panel for ``technique`` against ``events`` over rules whose logsource matches
    ``logsource`` (a category string, or a category/product/service subset dict). ``events`` is a single
    event dict or a list; a deduped class fires if its representative fires on ANY event (entity-level
    corroboration — the flagged entity did *something* a community rule recognizes). Returns
    ``{tagged, relevant, classes, evaluated, fired, skipped}``."""
    evs = [events] if isinstance(events, dict) else list(events)
    sel = _as_selector(logsource)
    rules = gather(technique, root=root)
    relevant = [(p, r) for p, r in rules if _ls_match(r, sel)]

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
        if any(rule_fires(rep_r, e) for e in evs):
            fired.append((rep_p.name, sorted(sig[1]), len(members)))
    return {"tagged": len(rules), "relevant": len(relevant), "classes": len(classes),
            "evaluated": evaluated, "fired": fired, "skipped": skipped}


def corroborate(technique: str, events, logsource="process_access",
                *, root: Path = SIGMA) -> dict:
    """Belnap-style corroboration of a canon finding by the deduped external panel. Adds ``votes``,
    ``belnap`` (TRUE | NONE — never FALSE), and a human ``verdict`` to the :func:`panel` result."""
    res = panel(technique, events, logsource, root=root)
    votes = len(res["fired"])
    if votes > 0:
        belnap, verdict = TRUE, f"CORROBORATED-true ({votes} independent deduped vote(s))"
    elif res["evaluated"] == 0:
        belnap, verdict = NONE, "NONE (no class evaluable here — panel abstains, doesn't contradict)"
    else:
        belnap, verdict = NONE, "UNCORROBORATED (panel evaluated but none fired — canon-only finding)"
    return {**res, "votes": votes, "belnap": belnap, "verdict": verdict}


def coverage_category(res: dict) -> str:
    """Classify a panel result into the honest corroboration spectrum — turning the gap into data:

      CORROBORATED         ≥1 deduped class fires (an external witness confirms)
      no-overlap           rules ran but none fired (community rules cover a different artifact/family)
      not-evaluable        same-logsource rules exist but none in the evaluable subset (operators/shape)
      no-same-logsource    no rule of the detector's logsource is tagged for the technique at all
    """
    if res["votes"] > 0:
        return "CORROBORATED"
    if res["relevant"] == 0:
        return "no-same-logsource"
    if res["evaluated"] == 0:
        return "not-evaluable"
    return "no-overlap"


def corroboration_coverage(specs: list[dict]) -> list[dict]:
    """Per-detector corroboration coverage against the real Sigma corpus. Each spec is
    ``{technique, logsource, events, note?}``; returns a record per spec with the panel counts, the
    :func:`coverage_category`, the firing rule-classes, and any author ``note`` (e.g. a detection-model
    or field-name caveat the counts alone don't convey). This is the recorded artifact behind the claim
    "what can the external panel actually corroborate" — honest negatives included, never silent."""
    out = []
    for s in specs:
        res = corroborate(s["technique"], s["events"], s["logsource"])
        out.append({"technique": s["technique"], "logsource": str(s["logsource"]),
                    "tagged": res["tagged"], "relevant": res["relevant"], "classes": res["classes"],
                    "evaluated": res["evaluated"], "votes": res["votes"],
                    "category": coverage_category(res),
                    "fired": [name for name, _f, _n in res["fired"]], "note": s.get("note", "")})
    return out


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
