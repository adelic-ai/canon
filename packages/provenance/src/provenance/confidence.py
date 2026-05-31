"""The confidence fold — graded belief in log-odds, fused Chair–Varshney style.

Contract: architecture spine §3 (confidence row) + §5/§6(ii). The named math is
**Chair–Varshney optimal LLR fusion** (Chair & Varshney 1986): when independent detectors
observe one hypothesis, the Bayes-optimal combiner is the **sum of their log-likelihood
ratios** in log-odds (logit) space — closed-form, not an approximation, because the
radar/CFAR-derived detectors have genuinely known operating points (Pd, Pfa). Summation is
associative + commutative, so it is a clean fold; the additive identity is **LLR 0 = no
evidence**.

The load-bearing design rule (§6(ii), carrier.md): **graded belief and knowledge value are
two orthogonal axes and must both be carried per node, never collapsed into one scalar.** A
:class:`Confidence` therefore holds *both*:

* ``log_odds`` — the graded belief (a float LLR; ``None`` = no evidence = the additive
  identity), and
* ``belnap`` — the Belnap knowledge status (:class:`~provenance.carrier.Four`).

These are not redundant. Two detectors that confidently disagree fuse to ``log_odds ≈ 0``
*and* ``belnap = BOTH``: the graded axis looks like equipoise ("0.5"), but the knowledge
axis records a **contradiction**, which is the soundness signal — *not* genuine 50/50. That
is exactly the conflation carrier.md exists to prevent.

The fold accumulates the knowledge axis by :func:`~provenance.carrier.kjoin` (proven
``≤_k``-monotone, so the fold satisfies the universal invariant on its knowledge
projection) and the graded axis by LLR summation.

Don't use Dempster's rule as the backbone (non-associative under conflict → breaks the
fold property); the Belnap ``BOTH`` carries the explicit-contradiction idea instead.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from provenance.carrier import FALSE, NONE, TRUE, Four, kjoin
from provenance.entity import Entity
from provenance.interpret import lineage


@dataclass(frozen=True, slots=True)
class Confidence:
    """Per-node confidence: two orthogonal axes, never collapsed.

    ``belnap`` is the knowledge status; ``log_odds`` is the graded belief (LLR), or ``None``
    for no evidence (the additive identity).
    """

    belnap: Four
    log_odds: float | None

    @property
    def probability(self) -> float | None:
        """The graded belief as a probability via the logistic (sigmoid) link, or ``None``."""
        if self.log_odds is None:
            return None
        return 1.0 / (1.0 + math.exp(-self.log_odds))

    @classmethod
    def from_detector(cls, fired: bool, *, pd: float, pfa: float) -> "Confidence":
        """A detector leaf from its operating point (Pd, Pfa) and its decision.

        The Chair–Varshney per-detector LLR weight: a detector that **fired** contributes
        ``log(Pd/Pfa)`` (evidence *for* the hypothesis → ``TRUE`` knowledge); one that did
        **not** fire contributes ``log((1-Pd)/(1-Pfa))`` (evidence *against* → ``FALSE``).
        """
        if not (0.0 < pd < 1.0 and 0.0 < pfa < 1.0):
            raise ValueError(f"operating point needs 0<pd,pfa<1, got pd={pd}, pfa={pfa}")
        if fired:
            return cls(TRUE, math.log(pd / pfa))
        return cls(FALSE, math.log((1.0 - pd) / (1.0 - pfa)))


#: The fold identity: no knowledge, no evidence. Fusing it changes nothing.
NO_EVIDENCE = Confidence(NONE, None)


def _add_log_odds(a: float | None, b: float | None) -> float | None:
    """Sum two LLRs with ``None`` as the additive identity (no evidence)."""
    if a is None:
        return b
    if b is None:
        return a
    return a + b


def _fuse(a: Confidence, b: Confidence) -> Confidence:
    """Fuse two confidences: knowledge by kjoin (≤_k-monotone), belief by LLR sum."""
    return Confidence(kjoin(a.belnap, b.belnap), _add_log_odds(a.log_odds, b.log_odds))


def confidence(
    root: Entity,
    *,
    evidence: dict[str, Confidence] | None = None,
) -> dict[str, Confidence]:
    """Fold the DAG to a :class:`Confidence` per node, keyed by ``Entity.id``.

    ``evidence`` maps a node id to that node's *own* leaf confidence (a detector decision,
    typically via :meth:`Confidence.from_detector`); a node without one seeds
    :data:`NO_EVIDENCE`. A node's confidence is its own evidence fused with every input's
    fused confidence — so the root accumulates all upstream evidence (Chair–Varshney over
    the dataflow). The root's value is ``result[root.id]``.
    """
    evidence = evidence or {}
    out: dict[str, Confidence] = {}
    for node in lineage(root):  # dependency order: every child precedes its parent
        acc = evidence.get(node.id, NO_EVIDENCE)
        if node.producer is not None:
            for child in node.producer.used:
                acc = _fuse(acc, out[child.id])
        out[node.id] = acc
    return out
