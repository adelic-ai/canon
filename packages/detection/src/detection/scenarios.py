"""Fidelity scenarios — the labeled data lives in the standalone ``synthcyber`` generator (data-production
outside the engine, per ``design/engine_workspace_boundary.md``). canon **consumes** it: ``variant_coverage``
runs the Sigma rules over the synthetic instances. The ``Scenario`` types/data are re-exported for convenience.
"""

from __future__ import annotations

# data-production (generator) — re-exported so existing callers keep working
from synthcyber.scenarios import Scenario, scenario_positives, t1003_001_scenarios  # noqa: F401


def variant_coverage(scenarios: list[Scenario], *, sigma_root=None) -> list[dict]:
    """Per (variant, channel): is there ≥1 evaluable Sigma rule that catches its events, and which. The
    defense-in-depth view — every key variant should be caught, ideally via its own channel. (Consumer: it
    runs canon's evaluator, so it lives here, not in the generator.)"""
    from detection.sigma_eval import evaluate_rule, is_evaluable
    from detection.sigma_panel import SIGMA, gather

    root = sigma_root or SIGMA
    out = []
    for s in scenarios:
        rules = [(p, r) for p, r in gather(s.technique, root=root) if is_evaluable(r)]
        catchers = [p.name for p, r in rules if any(evaluate_rule(r, e)["fires"] for e in s.events)]
        out.append({"technique": s.technique, "variant": s.variant, "channel": s.channel,
                    "caught": bool(catchers), "catchers": catchers})
    return out
