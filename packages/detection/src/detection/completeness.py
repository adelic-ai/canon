"""Partial-kill-chain completeness — score an attack *path* toward a crown jewel.

The design frame (``web/detection/kill_chains_as_entity_path_analysis.html``,
``design/kill_chains_as_entity_path_analysis.md``): a kill chain is an actor's
PATH toward a crown jewel, and threat-likelihood ≈ **completeness × abnormality**.
``chain.py`` is the *boolean* corner (did the whole ordered chain happen);
``shadow.py`` computes the *streaming prefix* completeness (``prefix / n_stages``).
This is the general **batch, gap-aware** form: given the target path and whatever
stages were observed (possibly gappy — 1, 2, 4 of 5), score it.

A hypothesis, in the chosen framing, is an attack-**path** scored by three things:
proximity to the crown jewel, intrusion-probability (the HMM likelihood, elsewhere),
and the identities it runs through. This module supplies the **path structure**: how
much is assembled, how far it reached, where the frontier is, and — the tie to the
entailment GAP — which stages are *internal gaps*: path steps BEFORE the deepest
observed one that were never seen. Because a later stage cannot be reached without
its predecessors, an internal gap is an **entailed-but-missing** step (a
:mod:`detection.entailment_gap` ``GAP`` candidate — "it happened, we didn't see it"),
distinct from *trailing* stages the attacker simply has not reached yet.

Two numbers, deliberately kept apart:
  * ``completeness`` = fraction of the path's stages observed (|seen| / |path|).
  * ``reach``        = crown-jewel proximity = (deepest observed index + 1) / |path|.
``reach ≥ completeness`` always; the gap between them is exactly the internal-gap
mass. A jewel touched with none of the lead-up seen is the loud case:
``reach = 1.0``, low ``completeness``, many internal GAPs — "the jewel was hit and
we are blind to how."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Completeness:
    """The scored path structure. ``frontier`` is the next FORWARD milestone (where
    the campaign goes next); ``internal_gaps`` are the BACKWARD entailed-but-missing
    steps to hunt for; ``trailing`` is the not-yet-reached remainder."""
    path: tuple[str, ...]
    completeness: float          # |seen ∩ path| / |path|
    reach: float                 # (deepest observed index + 1) / |path|  — proximity to the jewel
    complete: bool               # the terminal (crown-jewel) stage was observed
    assembled: tuple[str, ...]   # path stages observed, in path order
    frontier: str | None         # next expected milestone (None once complete)
    internal_gaps: tuple[str, ...]   # entailed-but-missing: unobserved path stages BEFORE the deepest reached
    trailing: tuple[str, ...]        # path stages after the deepest reached (not yet reached)


def chain_completeness(path: Iterable[str], observed: Iterable[str]) -> Completeness:
    """Score the ordered ``path`` (stages toward a crown jewel, first→last) against
    the ``observed`` stage names (order-independent, deduped; names not on the path
    are ignored). See the module docstring for the ``completeness`` vs ``reach``
    split and why internal gaps are entailment ``GAP`` candidates."""
    path = tuple(path)
    if not path:
        return Completeness((), 0.0, 0.0, False, (), None, (), ())

    on_path = set(path)
    seen = {s for s in observed if s in on_path}
    positions = [i for i, s in enumerate(path) if s in seen]
    deepest = max(positions) if positions else -1

    assembled = tuple(s for s in path if s in seen)
    completeness = len(seen) / len(path)
    reach = (deepest + 1) / len(path)
    complete = deepest == len(path) - 1
    frontier = path[deepest + 1] if deepest + 1 < len(path) else None
    internal_gaps = tuple(path[i] for i in range(deepest + 1) if path[i] not in seen)
    trailing = tuple(path[i] for i in range(deepest + 1, len(path)))

    return Completeness(
        path=path,
        completeness=round(completeness, 4),
        reach=round(reach, 4),
        complete=complete,
        assembled=assembled,
        frontier=frontier,
        internal_gaps=internal_gaps,
        trailing=trailing,
    )
