"""Per-anchor partial-chain posterior — a decaying belief that a crown jewel is under approach.

:mod:`detection.shadow` accumulates per-ACTOR chain prefixes. This is its per-ANCHOR
complement: for each crown-jewel(-adjacent) principal, accumulate the partial-chain
evidence *converging on it* into a decaying posterior — the warranted, gap-aware RISK
SIGNAL a response plane consumes (canon is a sensor, not an actuator; the actuation —
rotate / restrict / deceive — belongs to the PEP/PDP plane, and must not leak the
detection state). It anchors on the standing-suspect surface rather than trying to
resolve attacker identity, which is the tractable reframe.

The math is a naive-Bayes **log-odds accumulator with exponential forgetting**:
  * each evidence piece contributes a log-likelihood-ratio (LLR) to the anchor's log-odds;
  * between observations the accumulated evidence DECAYS back toward the prior — old
    pressure fades, so belief returns to the base rate if nothing fresh arrives.
The posterior probability is ``sigmoid(log-odds)``.

**Honest caveat (the ``verdict_coverage_space`` independence lesson).** Summing LLRs
assumes the evidence pieces are conditionally INDEPENDENT. Correlated evidence — the same
actor, one technique reused, a single campaign multi-counted — INFLATES the posterior, so
the score is an UPPER BOUND on belief until independence is measured (canon's MI /
coordination machinery). It is a graded, additive, absence-aware pressure signal, not a
calibrated probability of compromise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _logit(p: float) -> float:
    if not 0.0 < p < 1.0:
        raise ValueError(f"base_rate must be in (0, 1), got {p}")
    return math.log(p / (1.0 - p))


@dataclass
class AnchorBelief:
    """The accumulated state for one anchor. ``log_odds`` is the belief at ``last_time``;
    read it decayed-to-now via :meth:`AnchorPosterior.score`."""
    anchor: str
    log_odds: float
    last_time: float | None = None
    n_evidence: int = 0
    peak_log_odds: float = 0.0


class AnchorPosterior:
    """Accumulate partial-chain evidence per crown-jewel anchor into a decaying log-odds
    posterior. Stream evidence with :meth:`observe`; read the current belief with
    :meth:`score` / :meth:`probability`; rank the estate with :meth:`ranked`."""

    def __init__(self, *, base_rate: float = 0.01, decay_tau_sec: float = 6 * 3600.0) -> None:
        self.prior = _logit(base_rate)
        self.decay_tau_sec = decay_tau_sec
        self._beliefs: dict[str, AnchorBelief] = {}

    def _decayed(self, b: AnchorBelief, at: float | None) -> float:
        """``log_odds`` decayed from ``b.last_time`` to ``at``, toward the prior."""
        if at is None or b.last_time is None:
            return b.log_odds
        dt = max(0.0, at - b.last_time)
        return self.prior + (b.log_odds - self.prior) * math.exp(-dt / self.decay_tau_sec)

    def observe(self, anchor: str, llr: float, time: float) -> AnchorBelief:
        """Fold one evidence piece (a log-likelihood-ratio ``llr``) for ``anchor`` at
        event-clock ``time``: decay the standing belief to ``time``, then add ``llr``."""
        b = self._beliefs.get(anchor)
        if b is None:
            b = AnchorBelief(anchor=anchor, log_odds=self.prior, peak_log_odds=self.prior)
            self._beliefs[anchor] = b
        else:
            b.log_odds = self._decayed(b, time)      # forget old pressure before adding new
        b.log_odds += llr
        b.last_time = time
        b.n_evidence += 1
        b.peak_log_odds = max(b.peak_log_odds, b.log_odds)
        return b

    def score(self, anchor: str, at: float | None = None) -> float:
        """Current (optionally decayed-to ``at``) log-odds for ``anchor``; the prior for
        an anchor never observed."""
        b = self._beliefs.get(anchor)
        return self.prior if b is None else self._decayed(b, at)

    def probability(self, anchor: str, at: float | None = None) -> float:
        """The posterior probability = ``sigmoid(score)``. An upper bound (see caveat)."""
        return _sigmoid(self.score(anchor, at))

    def ranked(self, at: float | None = None) -> list[tuple[str, float]]:
        """Anchors ranked by posterior probability, highest pressure first."""
        return sorted(((a, self.probability(a, at)) for a in self._beliefs),
                      key=lambda x: x[1], reverse=True)


def chain_evidence(partial_chain, *, abnormality: float = 1.0, scale: float = 1.0) -> float:
    """Heuristic LLR contribution of a :class:`~detection.partial_chain.PartialChain`:
    proximity- and completeness-weighted, times the (data-gated) abnormality. Higher
    ``reach`` / ``completeness`` / ``abnormality`` → more evidence; a fully-assembled
    chain at the jewel contributes the most. **Not calibrated** — a monotone weighting to
    feed :meth:`AnchorPosterior.observe`; supply your own LLR when you have one."""
    c = partial_chain.completeness
    return scale * c.reach * c.completeness * abnormality
