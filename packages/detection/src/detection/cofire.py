"""Co-firing — fire every evaluable Sigma rule that *claims* a technique on a LABELED event set and
measure catch-layer **divergence**: of the rules co-claiming a technique, which actually catch which
labeled instances, and do they agree.

This closes the gap the channel proxy (``xcorp`` analyses) cannot. The proxy compares the *observable
channel* each corpus reads (metadata) and so works cross-corpus; it can only bound divergence from above.
Co-firing runs the rule logic on identical labeled events and observes the *catch-set* directly — same
channel, do they catch the same events. Two axes fall out:

* **catch-rate divergence** — of the co-claiming evaluable rules, how many fire at all. The fire/silent
  partition is the dominant signal on a single-variant dataset (the silent ones miss via field-name
  impedance or a logic gap, not absence — non-firing never refutes).
* **catch-set divergence** — among the rules that *do* fire, do they catch the same instances. Measured
  by the per-instance witness set and the mean pairwise Jaccard of catch-sets. This is muted when the
  malicious instances are near-identical (one variant); it needs variant diversity to be informative —
  the next synth increment, not a property of this measurement.

**Scope, stated honestly:**

* **Intra-Sigma only.** ESCU(SPL) and Elastic(EQL) have no execution engine in canon, so true *cross-corpus*
  co-firing is blocked until their logic is lowered into the IR (the motif path) or run on real engines.
  The cross-corpus catch-layer question is therefore still open; this measures the Sigma slice of it.
* **Test stand, not oracle.** On authored synthetic data the catch *rate* is not real-world recall — both
  sides were authored. What *is* faithful is the **relative** divergence between rules on identical input:
  which co-claiming rules agree, which are silent, which fire on the benign background.

Built on :func:`detection.sigma_panel.gather` (technique→rules), :func:`detection.sigma_eval.evaluate_rule`
(firing), and the instance-CID catch-set key from :mod:`detection.fidelity` (stage-4 catch-set grounding).
"""

from __future__ import annotations

import itertools
from collections import Counter
from pathlib import Path

from detection.fidelity import _cid
from detection.sigma_eval import evaluate_rule, is_evaluable
from detection.sigma_panel import SIGMA, gather


def _silent_cause(rule: dict, instances: list[tuple[str, dict]]) -> str:
    """Why a co-claiming rule caught no labeled instance — the same partition the fidelity scorecard uses:
    ``missing-telemetry`` (the rule's selection fields are absent from these events — wrong channel /
    field-name impedance), else ``logic-gap`` (fields present, values didn't match)."""
    sel = rule["detection"].get("selection")
    fields = {k.split("|")[0] for k in sel} if isinstance(sel, dict) else set()
    if fields and instances and all(not (fields & set(e)) for _cid_, e in instances):
        return "missing-telemetry"
    return "logic-gap"


def cofire(technique: str, events: list[dict], labels: list, *, sigma_root: Path = SIGMA) -> dict:
    """Fire every evaluable Sigma rule claiming ``technique`` on ``events`` (parallel ``labels``: truthy =
    a labeled malicious instance, falsy = benign background) and tally catch-layer divergence.

    Returns per-rule rows (``caught_on`` instance-CIDs + benign ``fps``) and the aggregate divergence:
    how many co-claimers catch at all, how the catchers' catch-sets overlap (mean pairwise Jaccard,
    instances caught by all/one/none), and the clean catchers (catch ≥1 malicious, zero benign FP)."""
    rules = [(p, r) for p, r in gather(technique, root=sigma_root) if is_evaluable(r)]
    malicious = [e for e, lab in zip(events, labels) if lab]
    benign = [e for e, lab in zip(events, labels) if not lab]
    instances = [(_cid(e), e) for e in malicious]
    inst_ids = [cid for cid, _ in instances]

    rows = []
    for p, r in rules:
        caught = sorted(cid for cid, e in instances if evaluate_rule(r, e)["fires"])
        fps = sum(1 for e in benign if evaluate_rule(r, e)["fires"])
        row = {"rule": p.name, "caught_on": caught, "n_caught": len(caught), "fps": fps}
        if not caught:
            row["silent_cause"] = _silent_cause(r, instances)
        rows.append(row)

    catching = [x for x in rows if x["n_caught"] > 0]
    silent = [x for x in rows if x["n_caught"] == 0]
    witness = {cid: [x["rule"] for x in catching if cid in x["caught_on"]] for cid in inst_ids}
    by_all = [c for c, w in witness.items() if catching and len(w) == len(catching)]
    by_one = [c for c, w in witness.items() if len(w) == 1]
    by_none = [c for c, w in witness.items() if not w]

    sets = [set(x["caught_on"]) for x in catching]
    jac = [len(a & b) / len(a | b) for a, b in itertools.combinations(sets, 2) if (a | b)]
    mean_jac = round(sum(jac) / len(jac), 3) if jac else (1.0 if len(catching) <= 1 else 0.0)

    return {
        "technique": technique,
        "rules_evaluable": len(rules),
        "rules_catching": len(catching),
        "n_malicious": len(malicious),
        "n_benign": len(benign),
        "catch_rate": round(len(catching) / len(rules), 3) if rules else 0.0,
        "instances_caught_by_all_catchers": len(by_all),
        "instances_caught_by_one": len(by_one),
        "instances_caught_by_none": len(by_none),
        "mean_pairwise_catch_jaccard": mean_jac,
        "clean_catchers": sorted(x["rule"] for x in catching if x["fps"] == 0),
        "catchers_with_fps": sorted(x["rule"] for x in catching if x["fps"] > 0),
        "silent_causes": dict(Counter(x["silent_cause"] for x in silent)),
        "rows": rows,
    }


def cofire_synth(technique: str, *, seed: int = 1, days: int = 5, sigma_root: Path = SIGMA) -> dict:
    """Wire the synth-enterprise generator straight into :func:`cofire`: build the inventory + causal
    timeline (seeded, reproducible), project it to labeled events, and co-fire the technique's rule
    bundle. The single entry point for "co-firing measurement on the synth generator"."""
    from detection.synth.emit import labeled_events
    from detection.synth.inventory import build_inventory
    from detection.synth.timeline import build_timeline

    inv = build_inventory(seed=seed)
    acts = build_timeline(inv, seed=seed, days=days)
    pairs = labeled_events(acts, inv)
    events = [e for e, _ in pairs]
    labels = [lab for _, lab in pairs]
    res = cofire(technique, events, labels, sigma_root=sigma_root)
    res["n_events"] = len(events)
    res["seed"] = seed
    return res
