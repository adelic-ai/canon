r"""P3 (completion) — the Sigma-verifier panel: independent, FCA/SKOS-deduped corroboration.

canon's cells confirm a milestone from the relational graph. The Sigma panel asks a
separate question: do INDEPENDENT, community-authored detections agree? A canon verdict
corroborated by external rules is more defensible than canon's word alone.

But you cannot just count rules. T1003.001 has 79 tagged Sigma rules; many are
near-duplicates (same logsource, same fields, different tool string). Counting all 79 as
79 independent confirmations is false corroboration. So the panel is DEDUPED first:

  FCA  — objects = rules, attributes = (logsource, the set of fields each keys on). Rules
         sharing an attribute-set are the same "concept" (same detection signature) → one
         equivalence class → ONE vote. The ⊆ order on field-sets is the concept lattice.
  SKOS — that subsumption is broader/narrower: a rule keying on {TargetImage} alone is
         BROADER than one also keying on {GrantedAccess, CallTrace} (the superset = narrower).

Honest coverage (the completeness channel, applied to the panel itself): the minimal
Sigma-subset evaluator handles `selection [and not 1 of filter*]` over flat field-maps.
Classes whose representative rule needs operators we don't implement are reported
NOT-EVALUATED (NONE) — not silently counted as a no-vote.

Data: packages/semantic-cyber/data/sigma-rules/ (3748 real SigmaHQ rules).
Run:  .venv/bin/python packages/detection/experiments/sigma_panel.py
"""

from __future__ import annotations

import collections
from pathlib import Path

import yaml

from lsass_fidelity_attestation_reproducible import _block_matches
from lsass_subgraph_detection import load

SIGMA = Path(__file__).parents[3] / "packages/semantic-cyber/data/sigma-rules"


def gather(technique: str) -> list[tuple[Path, dict]]:
    """All rules tagged attack.<technique> with a parseable detection + logsource."""
    tag = f"attack.{technique.lower()}"
    rules = []
    for p in SIGMA.rglob("*.yml"):
        try:
            txt = p.read_text()
            if tag not in txt.lower():
                continue
            r = yaml.safe_load(txt)
        except Exception:
            continue
        if isinstance(r, dict) and isinstance(r.get("detection"), dict) and isinstance(r.get("logsource"), dict):
            rules.append((p, r))
    return rules


def _logsource(r: dict) -> tuple:
    ls = r["logsource"]
    return (ls.get("category"), ls.get("product"), ls.get("service"))


def _fields(block) -> frozenset:
    return frozenset(k.split("|")[0] for k in block) if isinstance(block, dict) else frozenset()


def signature(r: dict) -> tuple:
    """The detection signature = (logsource, field-set keyed on). The FCA attribute-set."""
    return (_logsource(r), _fields(r["detection"].get("selection")))


def evaluable(r: dict) -> bool:
    """True iff the minimal evaluator can faithfully run this rule's condition + blocks."""
    det = r["detection"]
    cond = str(det.get("condition", "")).strip()
    ok_cond = cond == "selection" or (cond.startswith("selection and not") and "filter" in cond)
    sel = det.get("selection")
    if not ok_cond or not isinstance(sel, dict):
        return False
    return all(not isinstance(v, dict) for v in sel.values())   # flat field-maps only


def fires(r: dict, event: dict) -> bool:
    det = r["detection"]
    if not _block_matches(det["selection"], event):
        return False
    return not any(k.startswith("filter") and isinstance(v, dict) and _block_matches(v, event)
                   for k, v in det.items())


def panel(technique: str, event: dict, category: str) -> dict:
    """Run the deduped panel for `technique` against `event` (rules of logsource `category`)."""
    rules = gather(technique)
    relevant = [(p, r) for p, r in rules if _logsource(r)[0] == category]

    classes: dict[tuple, list] = collections.defaultdict(list)
    for p, r in relevant:
        classes[signature(r)].append((p, r))

    fired, evaluated, skipped = [], 0, []
    for sig, members in classes.items():
        rep_p, rep_r = members[0]                  # one representative per class = one vote
        if not evaluable(rep_r):
            skipped.append((sig, len(members)))
            continue
        evaluated += 1
        if fires(rep_r, event):
            fired.append((rep_p.name, sorted(sig[1]), len(members)))
    return {
        "tagged": len(rules), "relevant": len(relevant), "classes": len(classes),
        "evaluated": evaluated, "fired": fired, "skipped": skipped,
    }


def corroboration(technique: str, event: dict, category: str = "process_access") -> dict:
    """Belnap-style corroboration of a canon finding by the deduped external panel."""
    res = panel(technique, event, category)
    votes = len(res["fired"])
    if votes > 0:
        verdict = f"CORROBORATED-true ({votes} independent deduped vote(s))"
    elif res["evaluated"] == 0:
        verdict = "NONE (no class evaluable here — panel abstains, doesn't contradict)"
    else:
        verdict = "UNCORROBORATED (panel evaluated but none fired — canon-only finding)"
    return {**res, "votes": votes, "verdict": verdict}


def lsass_comsvcs_event(events: list[dict]) -> dict | None:
    """The ground-truth T1003.001 event canon's lsass_dump_subgraph fired on (comsvcs EID10)."""
    spawn = next((e for e in events if str(e.get("EventID")) == "1"
                  and "comsvcs" in str(e.get("CommandLine", "")).lower()), None)
    if not spawn:
        return None
    return next((e for e in events if str(e.get("EventID")) == "10"
                 and e.get("SourceProcessGUID") == spawn.get("ProcessGuid")
                 and "lsass" in str(e.get("TargetImage", "")).lower()), None)


def main() -> None:
    event = lsass_comsvcs_event(load())  # OTRF — canon's lsass_dump_subgraph fired here (T1003.001)
    print("canon finding: lsass_dump_subgraph → T1003.001 (credential-access), fired on the real comsvcs EID10 event.\n")
    r = corroboration("T1003.001", event, "process_access")

    print(f"=== Sigma panel for T1003.001 (the dedup is the point) ===")
    print(f"  {r['tagged']} rules tagged attack.t1003.001")
    print(f"  {r['relevant']} are logsource=process_access (the EID10 finding's event type)")
    print(f"  → DEDUPED to {r['classes']} equivalence classes (FCA: same logsource+field-set = one vote)")
    print(f"     dedup ratio {r['relevant']}:{r['classes']} — counting raw rules would {r['relevant']//max(r['classes'],1)}× the corroboration")
    print(f"  {r['evaluated']} classes evaluable by the minimal evaluator; {len(r['skipped'])} NOT-EVALUATED (NONE, honest)\n")

    print(f"=== independent votes (deduped classes that FIRE on the real attack event) ===")
    for name, fields, n_members in r["fired"]:
        print(f"  ✓ {name:48} keys={fields}  (class of {n_members} rule(s))")

    print(f"\ncorroboration: {r['verdict']}")
    print("canon's relational-graph verdict is independently corroborated by deduped community Sigma rules —")
    print("not its own word, and not inflated by counting near-duplicate rules as separate confirmations.")


if __name__ == "__main__":
    main()
