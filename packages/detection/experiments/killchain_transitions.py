r"""The kill-chain progression model — learned from REAL attack sequences.

The orchestration spine (hole #2) + the structured-proposer transition model
(hole #1's HMM): which milestone (ATT&CK tactic) follows which, and which are
entry points — learned from the 40 real incidents in attack-flow-corpus (MITRE
Attack Flow / STIX). This is the HMM transition matrix, the search priors, and
the forward-progression model the cells/orchestrator need, on real data (not a
hand-coded kill chain).

Each flow is a DAG of attack-action nodes (carrying tactic_id + technique_id)
connected through attack-condition / attack-operator nodes via *_refs edges. We
hop over the condition/operator nodes to get action→action transitions, then
aggregate tactic→tactic transitions across all incidents.

Data: ~/data/attack-flow-corpus/  (40 STIX Attack-Flow files).
Run:  .venv/bin/python packages/detection/experiments/killchain_transitions.py
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

CORPUS = Path.home() / "data/attack-flow-corpus"

# ATT&CK tactic id → short name (the kill-chain milestones, left→right)
TACTIC = {
    "TA0043": "recon", "TA0042": "resource-dev", "TA0001": "initial-access",
    "TA0002": "execution", "TA0003": "persistence", "TA0004": "priv-esc",
    "TA0005": "defense-evasion", "TA0006": "credential-access", "TA0007": "discovery",
    "TA0008": "lateral-movement", "TA0009": "collection", "TA0011": "command-control",
    "TA0010": "exfiltration", "TA0040": "impact",
}


def _tactic(action: dict) -> str | None:
    tid = action.get("tactic_id") or ""
    return TACTIC.get(tid, tid or None)


def _out_refs(obj: dict) -> list[str]:
    """All outgoing edge targets — any field ending in _refs (effect_refs,
    on_true_refs, on_false_refs, on_completion_refs, …). Defensive to schema."""
    out: list[str] = []
    for k, v in obj.items():
        if k.endswith("_refs") and isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


def _downstream_actions(action: dict, by_id: dict[str, dict]) -> list[dict]:
    """Resolve the next attack-action(s), hopping over condition/operator nodes."""
    seen, stack, actions = set(), list(_out_refs(action)), []
    while stack:
        rid = stack.pop()
        if rid in seen:
            continue
        seen.add(rid)
        nxt = by_id.get(rid)
        if not nxt:
            continue
        if nxt.get("type") == "attack-action":
            actions.append(nxt)
        else:  # condition / operator / asset — hop through it
            stack.extend(_out_refs(nxt))
    return actions


def main() -> None:
    files = sorted(CORPUS.rglob("*.json"))
    files = [f for f in files if f.name != "manifest.json"]
    transitions: collections.Counter = collections.Counter()
    starts: collections.Counter = collections.Counter()
    flows_parsed = 0

    for f in files:
        try:
            objs = json.loads(f.read_text()).get("objects", [])
        except (json.JSONDecodeError, AttributeError):
            continue
        by_id = {o["id"]: o for o in objs if isinstance(o, dict) and "id" in o}
        actions = [o for o in objs if o.get("type") == "attack-action"]
        if not actions:
            continue
        flows_parsed += 1
        # which actions have an incoming edge? (the rest are flow entry points)
        has_incoming = set()
        for o in objs:
            if isinstance(o, dict):
                for r in _out_refs(o):
                    has_incoming.add(r)
        for a in actions:
            ta = _tactic(a)
            if ta and a["id"] not in has_incoming:
                starts[ta] += 1
            for nxt in _downstream_actions(a, by_id):
                tb = _tactic(nxt)
                if ta and tb and ta != tb:           # tactic-level transition (skip self-loops)
                    transitions[(ta, tb)] += 1

    print(f"parsed {flows_parsed}/{len(files)} real attack-flow incidents\n")

    print("=== ENTRY PRIORS — which tactic an attack STARTS at (the left of ATT&CK) ===")
    total_starts = sum(starts.values()) or 1
    for t, n in starts.most_common(8):
        print(f"  {t:18} {n:3}  ({n/total_starts:.0%})")

    print("\n=== TRANSITION MODEL — which milestone follows which (top, across all incidents) ===")
    for (a, b), n in transitions.most_common(15):
        print(f"  {a:18} → {b:18} {n:3}")

    # forward-progression: from each tactic, its most likely next (the Markov row)
    nexts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for (a, b), n in transitions.items():
        nexts[a][b] += n
    print("\n=== FORWARD-PROGRESSION — given a milestone, the most likely next (HMM transition row) ===")
    for a in ("initial-access", "execution", "credential-access", "discovery", "lateral-movement"):
        if a in nexts:
            tot = sum(nexts[a].values())
            top = ", ".join(f"{b} {c/tot:.0%}" for b, c in nexts[a].most_common(3))
            print(f"  {a:18} → {top}")

    print("\nThis is the HMM transition matrix / search priors / forward-progression model, learned")
    print("from real incidents — the orchestration spine (#2) + the structured proposer (#1), data-backed.")


if __name__ == "__main__":
    main()
