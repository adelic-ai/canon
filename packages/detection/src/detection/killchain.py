"""Kill-chain transition model — learned tactic→tactic progression from real attack sequences.

The orchestrator's search prior: which ATT&CK tactic (milestone) tends to follow which, learned by
parsing MITRE Attack-Flow (STIX) incidents rather than hand-coding a kill chain. Each flow is a DAG
of attack-action nodes (carrying ``tactic_id``) joined through attack-condition/operator nodes via
``*_refs`` edges; we hop over the non-action nodes to recover action→action transitions and aggregate
them to tactic→tactic counts across all incidents.

Promoted from experiments with the corpus path parameterized (no hardcoded location). The forward
rows (:func:`forward_nexts`) are the orchestrator's "where to look next" priors; the entry-prior
counts (the ``starts`` return) are indicative only — the no-incoming-edge heuristic over-counts
roots, and Attack-Flow incidents often begin where reporting began, not at true initial-access.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

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
    """All outgoing edge targets — any field ending in ``_refs`` (effect_refs, on_true_refs, …).
    Defensive to the schema variants across the corpus."""
    out: list[str] = []
    for k, v in obj.items():
        if k.endswith("_refs") and isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    return out


def _downstream_actions(action: dict, by_id: dict[str, dict]) -> list[dict]:
    """The next attack-action(s), hopping over condition/operator/asset nodes."""
    seen: set[str] = set()
    stack = list(_out_refs(action))
    actions: list[dict] = []
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
        else:
            stack.extend(_out_refs(nxt))
    return actions


def build_model(corpus: str | Path) -> tuple[collections.Counter, collections.Counter, int, int]:
    """Parse the Attack-Flow ``corpus`` directory → (tactic→tactic transition counts, start-tactic
    counts, flows_parsed, n_files). Importable so the orchestrator drives its search off this model."""
    files = [f for f in sorted(Path(corpus).rglob("*.json")) if f.name != "manifest.json"]
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
        has_incoming: set[str] = set()
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
    return transitions, starts, flows_parsed, len(files)


def forward_nexts(transitions: collections.Counter) -> dict[str, list[tuple[str, float]]]:
    """``{tactic: [(next_tactic, prob), ...] desc}`` — the forward search priors / HMM transition rows."""
    nexts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for (a, b), n in transitions.items():
        nexts[a][b] += n
    return {a: [(b, n / sum(c.values())) for b, n in c.most_common()] for a, c in nexts.items()}
