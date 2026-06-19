"""Adversarial semantics gate — the labeled cases live in the standalone ``synthcyber`` generator; canon
**consumes** them here: ``attest_corpus`` runs both emitters and checks correctness (oracle == expected) +
parity (python == sparql), localized by landmine. The ``AdversarialCase``/``adversarial_corpus`` data are
re-exported for convenience.

This is where the generator earns its keep on the semantics axis: a green report = the emitters conform to the
pinned profile on every landmine; a red one localizes exactly which semantic diverged.
"""

from __future__ import annotations

# data-production (generator) — re-exported so existing callers keep working
from synthcyber.adversarial import AdversarialCase, adversarial_corpus  # noqa: F401

from detection.fidelity import _cid
from detection.motif import eval_python, eval_sparql, from_sigma


def attest_corpus(cases: list[AdversarialCase] | None = None) -> dict:
    """Run both emitters over the corpus; report **correctness** (oracle == expected) and **parity**
    (python == sparql) per case, localized by landmine. Content-addressed so the conformance claim re-derives.
    ``incorrect`` should be empty (the oracle conforms to the pinned spec); ``divergent`` should be empty too
    (full emitter parity)."""
    cases = cases if cases is not None else adversarial_corpus()
    rows, incorrect, divergent = [], [], []
    for c in cases:
        g = from_sigma(c.rule)
        py = eval_python(g, c.event)
        sp = eval_sparql(g, c.event)
        row = {"landmine": c.landmine, "expected": c.expected, "python": py, "sparql": sp,
               "correct": py == c.expected, "agree": py == sp}
        rows.append(row)
        if not row["correct"]:
            incorrect.append(row)
        if not row["agree"]:
            divergent.append(row)
    body = {"n": len(cases), "rows": rows}
    return {
        "n": len(cases),
        "oracle_correct": not incorrect,
        "emitters_agree": not divergent,
        "incorrect": incorrect,
        "divergent": divergent,
        "divergent_landmines": sorted({r["landmine"] for r in divergent}),
        "by_landmine": {r["landmine"]: r for r in rows},
        "cid": _cid(body),
    }
