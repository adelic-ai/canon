"""Partial-kill-chain composition — observed techniques → one hypothesis object.

The composition the June/July survey called the "missing narrative spine": it turns
a partial, time-ordered technique sequence into a single partial-kill-chain
*hypothesis* by composing four already-tested modules, and it **adds no algorithm of
its own** — every real computation lives in the modules it calls, so the composition
itself has nothing to get wrong:

  1. :func:`detection.hmm.decode_gated`      observed techniques → the hidden TACTIC
                                             path (Viterbi where the corpus emits the
                                             technique, the 1:1 map where it doesn't).
  2. :func:`detection.chain_completeness`    score that decoded path against the target
                                             path toward a crown jewel → completeness,
                                             reach (proximity), frontier, internal gaps.
  3. :func:`detection.killchain.forward_nexts`  attach P(frontier | deepest reached) —
                                             the transition-prior for the next milestone.
  4. :func:`detection.classify_entailment`   (optional) refine each stage-level internal
                                             gap to motif grain: GAP (entailed, channel
                                             collected) vs NONE (unobservable).

The result is the "path scored by proximity × intrusion-probability × identities"
shape: this supplies the path structure and the transition-prior; intrusion-probability
in full and identities come from the caller's context. The HMM model
(``transitions``/``starts``/``emissions``) is passed in rather than built here, so the
composition is pure and unit-testable on a synthetic model (no corpus dependency).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from detection.completeness import Completeness, chain_completeness
from detection.entailment_gap import Entailment, classify_entailment
from detection.hmm import decode_gated
from detection.killchain import forward_nexts


@dataclass(frozen=True)
class PartialChain:
    """One partial-kill-chain hypothesis. ``completeness`` embeds the full
    :class:`~detection.completeness.Completeness` (path, reach, frontier, internal
    gaps, trailing); this adds the HMM-decoded tactics, the frontier's transition
    probability, and any motif-grain gap refinement."""
    observations: tuple[str, ...]        # the input technique sequence
    decoded: tuple[str, ...]             # hidden tactic per observation (HMM, gated)
    observed_tactics: tuple[str, ...]    # distinct decoded tactics, first-seen order
    completeness: Completeness           # the scored path structure
    frontier_prob: float | None          # P(frontier | deepest reached) from the Markov model
    gap_findings: dict                   # {stage: classify_entailment(...)} for refined internal gaps


def compose_partial_chain(
    observations,
    target_path,
    *,
    transitions: Counter,
    starts: Counter,
    emissions: dict[str, dict[str, float]],
    fallback: dict[str, str] | None = None,
    gap_entailments: dict[str, Entailment] | None = None,
    events: list[dict] | None = None,
) -> PartialChain:
    """Compose the four modules into a single hypothesis. ``target_path`` is the
    ordered stage/tactic sequence toward the crown jewel; ``fallback`` is the 1:1
    technique→tactic map for the decode gate. Pass ``gap_entailments`` (``{stage:
    Entailment}``) + ``events`` to refine internal gaps to motif grain."""
    decoded = tuple(decode_gated(
        list(observations), fallback=fallback or {},
        transitions=transitions, starts=starts, emissions=emissions,
    ))
    observed_tactics = tuple(dict.fromkeys(decoded))          # order-preserving dedup
    comp = chain_completeness(target_path, observed_tactics)

    # P(frontier | deepest reached) — the transition prior for the next milestone.
    frontier_prob = None
    if comp.frontier is not None and comp.assembled:
        deepest = comp.assembled[-1]
        nexts = dict(forward_nexts(transitions).get(deepest, []))
        frontier_prob = round(nexts.get(comp.frontier, 0.0), 4)

    # Optional motif-grain refinement: for each stage-level internal gap that has an
    # entailment, is the absence a GAP (channel collected) or NONE (unobservable)?
    gap_findings: dict = {}
    if gap_entailments and events is not None:
        for stage in comp.internal_gaps:
            ent = gap_entailments.get(stage)
            if ent is not None:
                gap_findings[stage] = classify_entailment(ent, events)

    return PartialChain(
        observations=tuple(observations),
        decoded=decoded,
        observed_tactics=observed_tactics,
        completeness=comp,
        frontier_prob=frontier_prob,
        gap_findings=gap_findings,
    )
