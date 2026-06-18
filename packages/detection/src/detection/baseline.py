"""Per-entity baselines — a learned parameter, the *algorithm* half of the engine/workspace cut.

Pure functions, no I/O and no workspace: the LEARNING lives here (engine, ships with canon); the learned
VALUES live in the workspace's parameters store (:mod:`detection.workspace`). The model-code vs model-weights
line (``design/engine_workspace_boundary.md`` §3) made concrete.

A baseline tracks **additive sufficient statistics** per entity — ``n`` (count), ``sum`` and ``sumsq`` of a
numeric observation — so two baselines COMBINE by summing (:func:`blend_baselines`). That is what lets the
parameter *grow* as canon is re-run over more data: each run adds its statistics to the stored prior.

Estimates use **Bühlmann credibility** (the actuarial per-entity baseline): an entity's own mean blended with
the population mean, weight ``Z = n / (n + K)`` rising with the entity's data volume — *more data on an entity
→ more credible its own baseline*, exactly the "grows/sharpens as run" property. ``K`` is a fixed credibility
constant here (a fuller version estimates it from the between/within-entity variance ratio).
"""

from __future__ import annotations

_DEFAULT_K = 20.0


def learn_entity_baseline(events: list[dict], *, entity: str, value: str, K: float = _DEFAULT_K) -> dict:
    """Learn per-entity sufficient statistics of the numeric ``value`` field, grouped by the ``entity`` field.
    Non-numeric/absent values are skipped (counted in neither ``n`` nor the sums)."""
    ent: dict[str, dict] = {}
    for e in events:
        try:
            x = float(e.get(value))
        except (TypeError, ValueError):
            continue
        k = str(e.get(entity, ""))
        s = ent.setdefault(k, {"n": 0, "sum": 0.0, "sumsq": 0.0})
        s["n"] += 1
        s["sum"] += x
        s["sumsq"] += x * x
    return {"entities": ent, "K": K}


def blend_baselines(prior: dict | None, observed: dict) -> dict:
    """Combine a stored ``prior`` baseline with a freshly-``observed`` one by summing sufficient statistics
    per entity — additive, so re-running over new data *accumulates* (the parameter grows). ``prior=None``
    (first run) → ``observed`` unchanged."""
    if prior is None:
        return observed
    K = observed.get("K", prior.get("K", _DEFAULT_K))
    ent = {k: dict(v) for k, v in prior["entities"].items()}
    for k, s in observed["entities"].items():
        t = ent.setdefault(k, {"n": 0, "sum": 0.0, "sumsq": 0.0})
        t["n"] += s["n"]
        t["sum"] += s["sum"]
        t["sumsq"] += s["sumsq"]
    return {"entities": ent, "K": K}


def credibility_estimates(baseline: dict) -> dict:
    """Derive each entity's credibility-blended estimate from the (additive) baseline: ``estimate = Z·own_mean
    + (1−Z)·pop_mean``, ``Z = n/(n+K)``. As an entity accrues data across runs, ``Z → 1`` and the estimate
    moves from the population mean toward the entity's own mean."""
    ent = baseline["entities"]
    K = baseline.get("K", _DEFAULT_K)
    tot_n = sum(s["n"] for s in ent.values())
    tot_sum = sum(s["sum"] for s in ent.values())
    pop_mean = tot_sum / tot_n if tot_n else 0.0
    out = {}
    for k, s in ent.items():
        own = s["sum"] / s["n"] if s["n"] else 0.0
        Z = s["n"] / (s["n"] + K)
        out[k] = {"n": s["n"], "own_mean": own, "pop_mean": pop_mean,
                  "Z": Z, "estimate": Z * own + (1.0 - Z) * pop_mean}
    return out
