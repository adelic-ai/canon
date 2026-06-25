"""Shadow accumulator — the STREAMING counterpart to :mod:`detection.chain`'s batch checker.

:mod:`detection.chain` recognizes *complete* chains in *batch* (forensic — "did this whole path happen").
This fires on a **prefix, online**: maintain a sparse set of per-entity *shadows* (partial chain matches),
advance each as events arrive in time order, **decay** a shadow's weight with age, prune stale ones, and raise
an early-warning the moment a shadow assembles ``fire_at_prefix`` stages — *before* the chain completes (before
the crown-jewel pivot). A completed chain is a failure; the prefix is the warning.

This is the **third online stateful shape** (``web/online_partial_chain_detection.html``), between the
per-event verifier (stateless) and the windowed surfacer (one trailing window).

**Tractable by sparsity.** A shadow exists only for an entity that has reached stage 0; the live set is the
handful mid-something, not the population. ``n_instantiated`` vs the actor count is the sparsity measured.

**One forgetting operator, two carriers.** :func:`_forget` is the EWMA recurrence ``α·obs + (1−α)·old``; the
shadow's ``weight`` decays by its continuous-time sibling ``w·exp(−Δt/τ)``. Same family (the design note's
"structurally the same, conceptually distinct"): the baseline forgets a *level*, the shadow forgets a
*hypothesis weight*. :mod:`detection.baseline` is the *batch* per-entity sibling (additive sufficient stats +
credibility); this is the *streaming* form.

**Faithful to the batch checker.** Stage advance reuses :mod:`detection.chain`'s time-yielding stage predicates
UNCHANGED, threaded forward by ``not_before`` exactly as :func:`detection.chain.check_chain` does — so online
prefix semantics match the batch checker on the stages seen so far. Stages are evaluated over the actor's
accumulated events (window predicates like the fan-out need the set); the per-event re-eval is
``O(events/actor)`` and the incremental/CEP state optimization is deferred (the note's "CEP is the impl.").
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from detection.chain import _ts, group_by_actor  # noqa: F401  (group_by_actor re-exported for callers)


def _forget(old: float, obs: float, alpha: float) -> float:
    """The EWMA recurrence — the shared forgetting operator. ``alpha`` in (0,1]: higher = forget faster."""
    return alpha * obs + (1.0 - alpha) * old


@dataclass
class Shadow:
    """A live partial-match: how far an entity's chain prefix has assembled, and how hot the hypothesis is."""
    actor: str
    prefix: int                                  # stages satisfied so far (the assembled prefix length)
    stage_times: list[float] = field(default_factory=list)
    weight: float = 1.0                          # decays with age; refreshed to 1.0 on each advance
    last_time: float | None = None               # event-clock time of the last touch (for decay)
    fired: bool = False


@dataclass
class Alert:
    """An early-warning raised when a shadow reaches ``fire_at_prefix`` — before chain completion."""
    actor: str
    prefix: int
    n_stages: int
    completeness: float                          # prefix / n_stages  (< 1.0 ⇒ fired before completion)
    time: float                                  # event-clock time the prefix completed (the alert time)
    weight: float
    abnormality: float                           # fan-out vs the population baseline at fire time


class ShadowAccumulator:
    """Stream events through :meth:`observe`; get an :class:`Alert` when a kill-chain *prefix* assembles.

    ``stages`` is :mod:`detection.chain`'s ``[(name, predicate)]`` form. ``fire_at_prefix`` < ``len(stages)``
    makes it an *early* warning (e.g. 2 of the 3 kerberoast stages = roast detected before the lateral pivot).
    ``decay_tau_sec`` is the hypothesis half-life scale; ``prune_below`` drops a cold shadow (and with it the
    carried prefix — which is how a too-short ``τ`` *loses a slow attacker*, the low-and-slow caveat made real).
    """

    def __init__(self, stages: list[tuple], *, actor_field: str, fire_at_prefix: int,
                 decay_tau_sec: float = 6 * 3600.0, prune_below: float = 0.05,
                 event_horizon_sec: float | None = None,
                 fanout_field: str = "Service_Name", baseline_alpha: float = 0.05,
                 abnormality_gate: float = 0.0) -> None:
        if not 1 <= fire_at_prefix <= len(stages):
            raise ValueError(f"fire_at_prefix must be in [1, {len(stages)}], got {fire_at_prefix}")
        self.stages = stages
        self.actor_field = actor_field
        self.fire_at_prefix = fire_at_prefix
        self.decay_tau_sec = decay_tau_sec
        self.prune_below = prune_below
        # The per-actor event buffer is bounded — compact state, not a replayed log. Events older than the
        # horizon age out, so a long-cold prefix CANNOT be resurrected by re-scanning history (which is what
        # makes decay load-bearing). Default ≫ τ so a warm in-progress chain is never starved.
        self.event_horizon_sec = event_horizon_sec if event_horizon_sec is not None else decay_tau_sec * 8
        self.fanout_field = fanout_field
        self.baseline_alpha = baseline_alpha
        self.abnormality_gate = abnormality_gate

        self._evs: dict[str, list[dict]] = {}
        self._shadows: dict[str, Shadow] = {}
        self.n_instantiated = 0                  # total shadows ever created (incl. prune→rebuild churn)
        self.peak_live = 0                       # max concurrent live shadows (the live-set size)
        self.max_prefix: dict[str, int] = {}     # deepest prefix each actor ever reached (survives pruning)
        # Population EWMA of per-actor cumulative fan-out — a one-pass-learnable "normal" the benign majority
        # sets. A PER-ACTOR longitudinal baseline (the better gate) is data-gated on history we don't have in
        # one pass — the recurring wall; baseline.py is its batch per-entity form.
        self._pop_fanout: float = 0.0

    @property
    def shadows(self) -> dict[str, Shadow]:
        return dict(self._shadows)

    def _fanout(self, evs: list[dict]) -> int:
        """Distinct fan-out targets seen for an actor (the kerberoast abnormality feature)."""
        return len({e.get(self.fanout_field) for e in evs
                    if e.get("EventCode") == "4769" and e.get(self.fanout_field) is not None})

    def observe(self, event: dict) -> list[Alert]:
        """Feed one event (stream order). Returns a one-element list on an early-warning, else empty."""
        actor = event.get(self.actor_field)
        if actor is None:
            return []
        t = _ts(event)
        if t is None:
            return []
        evs = self._evs.setdefault(actor, [])
        evs.append(event)
        # age out events past the horizon → bounded buffer, and a cold prefix can't be re-derived
        cutoff = t - self.event_horizon_sec
        evs = self._evs[actor] = [e for e in evs if (_ts(e) or 0.0) >= cutoff]

        sh = self._shadows.get(actor)
        # ── decay the existing hypothesis by elapsed event-time, prune if cold ──────────────────────
        if sh is not None and sh.last_time is not None:
            dt = max(0.0, t - sh.last_time)
            sh.weight *= math.exp(-dt / self.decay_tau_sec)
            if sh.weight < self.prune_below:
                del self._shadows[actor]           # hypothesis went cold — the carried prefix is forgotten
                sh = None

        # ── advance forward through any stages now satisfied (threaded not_before, like check_chain) ─
        prefix = sh.prefix if sh else 0
        not_before = sh.stage_times[-1] if sh and sh.stage_times else None
        advanced = False
        while prefix < len(self.stages):
            _name, pred = self.stages[prefix]
            st = pred(evs, not_before)
            if st is None:
                break
            if sh is None:
                sh = Shadow(actor=actor, prefix=0)
                self._shadows[actor] = sh
                self.n_instantiated += 1
            sh.prefix = prefix + 1
            sh.stage_times.append(st)
            self.max_prefix[actor] = max(self.max_prefix.get(actor, 0), sh.prefix)
            prefix += 1
            not_before = st
            advanced = True
        if advanced and sh is not None:
            sh.weight = 1.0                        # fresh evidence re-energizes the hypothesis
            sh.last_time = t
        elif sh is not None:
            sh.last_time = t

        self.peak_live = max(self.peak_live, len(self._shadows))

        # ── population baseline update + fire on prefix (gated by abnormality) ──────────────────────
        fanout = self._fanout(evs)
        abnormality = fanout / (self._pop_fanout + 1.0)   # vs population "normal"; +1 = cold-start prior
        self._pop_fanout = _forget(self._pop_fanout, float(fanout), self.baseline_alpha)

        if sh is not None and sh.prefix >= self.fire_at_prefix and not sh.fired \
                and abnormality >= self.abnormality_gate:
            sh.fired = True
            return [Alert(actor=actor, prefix=sh.prefix, n_stages=len(self.stages),
                          completeness=sh.prefix / len(self.stages), time=sh.stage_times[sh.prefix - 1],
                          weight=sh.weight, abnormality=abnormality)]
        return []

    def run(self, events: list[dict]) -> list[Alert]:
        """Convenience: sort by event time and stream the whole list. Returns all alerts in fire order."""
        alerts: list[Alert] = []
        for e in sorted(events, key=lambda e: (_ts(e) is None, _ts(e))):
            alerts.extend(self.observe(e))
        return alerts
