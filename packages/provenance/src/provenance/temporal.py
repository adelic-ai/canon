"""The temporal fold — chronicle recognition over an event-time annotation stream.

Contract: architecture spine §3 (temporal row) + §6 (the one seam that isn't free).
A small CEP/chronicle pattern algebra (Dousson; Morin & Debar for IDS) whose result is
carrier-valued (Belnap :class:`~provenance.carrier.Four`):

    TRUE  = Matched          FALSE = NotMatched
    NONE  = NotYetObservable (silent feed / partial data)   BOTH  = Conflicting

Three design rules from §6, all load-bearing:

1. **Temporal state lives *beside* the DAG, never as DAG mutation.** A pattern is
   recognized against a :class:`Trace` (an event-time annotation stream passed in),
   *not* by mutating the content-addressed provenance DAG. The DAG stays timeless.

2. **The detect/validate duality is one algebra.** :func:`Any` is ∃-detect (truth-join
   ``tjoin`` over alternatives — does *some* path match); :func:`All` is ∀-validate
   (truth-meet ``tmeet`` — do *all* required conditions hold). One pattern tree, read two
   ways. When a detect path and a validate path disagree, the carrier yields ``BOTH`` —
   the soundness alarm, for free.

3. **Negation under partial data is the hard seam — and it closes against the keystone.**
   "C never occurred in W" is ``TRUE`` on a *live* feed but must be ``NONE`` on a *silent*
   one (the absence-of-evidence trap, time-extended). This needs **no special case**: a
   leaf returns ``NONE`` when its channel is silent (feed-liveness *is* custody, §6/§3),
   and :func:`Never` is just carrier ``neg`` — which maps ``NONE→NONE``, ``FALSE→TRUE``,
   ``TRUE→FALSE``. So absent+live (``FALSE``) negates to ``TRUE`` and absent+silent
   (``NONE``) negates to ``NONE``, exactly as required. The seam closes through the
   carrier's own negation.

Every combinator is a carrier op (``tjoin``/``tmeet``/``neg``), all ``≤_k``-monotone, so
the fold satisfies the universal invariant. The leaves are ``≤_k``-monotone in the feed:
a silent channel (``NONE``) sits below the live verdict (``TRUE``/``FALSE``) it resolves to.
"""

from __future__ import annotations

from dataclasses import dataclass

from provenance.carrier import FALSE, NONE, TRUE, Four, neg, tjoin, tmeet


@dataclass(frozen=True, slots=True)
class Event:
    """A timestamped observation. ``time`` is event-time (the annotation), not wall-clock."""

    label: str
    time: float


@dataclass(frozen=True, slots=True)
class Trace:
    """The event-time annotation stream a pattern is recognized against.

    ``events`` are the observations; ``live`` is the set of channels (labels) whose feed is
    healthy — the feed-liveness/custody signal. A label **not** in ``live`` is a silent
    feed: its absence is unknown (``NONE``), never a confident negative.
    """

    events: tuple[Event, ...]
    live: frozenset[str]

    def of(self, label: str) -> tuple[Event, ...]:
        return tuple(e for e in self.events if e.label == label)


# ── pattern algebra (a small chronicle language) ─────────────────────────────────────
class Pattern:
    """Base of the pattern algebra. Recognize with :func:`recognize`."""


@dataclass(frozen=True, slots=True)
class Occurs(Pattern):
    """∃ an event with ``label``. Present → TRUE; absent on a *live* feed → FALSE; absent on
    a *silent* feed → NONE (the keystone: absence-of-evidence is not evidence-of-absence)."""

    label: str


@dataclass(frozen=True, slots=True)
class Window(Pattern):
    """∃ a ``label`` event with ``lo <= time <= hi``. Same liveness rule as :class:`Occurs`."""

    label: str
    lo: float
    hi: float


@dataclass(frozen=True, slots=True)
class Before(Pattern):
    """∃ an ``a`` event strictly preceding a ``b`` event (ordered sequence).

    Needs *both* channels live to decide: either silent → NONE. Both live and an a-before-b
    pair exists → TRUE; both live but no such ordering → FALSE.
    """

    a: str
    b: str


@dataclass(frozen=True, slots=True)
class Any(Pattern):
    """∃-detect: truth-join (``tjoin``) over alternatives — does *some* sub-pattern match."""

    parts: tuple[Pattern, ...]


@dataclass(frozen=True, slots=True)
class All(Pattern):
    """∀-validate: truth-meet (``tmeet``) over requirements — do *all* sub-patterns hold."""

    parts: tuple[Pattern, ...]


@dataclass(frozen=True, slots=True)
class Never(Pattern):
    """Temporal negation: carrier ``neg`` of the inner pattern. The §6 seam — NONE-preserving."""

    inner: Pattern


def _leaf_present(hits: tuple[Event, ...], label: str, trace: Trace) -> Four:
    """The liveness-gated verdict for a single-channel existence check."""
    if hits:
        return TRUE  # observed
    return FALSE if label in trace.live else NONE  # live⇒genuinely absent; silent⇒unknown


def recognize(pattern: Pattern, trace: Trace) -> Four:
    """Fold a :class:`Pattern` against a :class:`Trace` into a Belnap verdict.

    Combinators compose child verdicts via the carrier (``tjoin``/``tmeet``/``neg``); leaves
    do the temporal reasoning against the annotation stream. ``Any()``/``All()`` with no
    parts return their identity (FALSE for ∃-detect, TRUE for ∀-validate).
    """
    if isinstance(pattern, Occurs):
        return _leaf_present(trace.of(pattern.label), pattern.label, trace)

    if isinstance(pattern, Window):
        hits = tuple(e for e in trace.of(pattern.label) if pattern.lo <= e.time <= pattern.hi)
        return _leaf_present(hits, pattern.label, trace)

    if isinstance(pattern, Before):
        if pattern.a not in trace.live or pattern.b not in trace.live:
            return NONE  # either feed silent ⇒ ordering unknown
        a_events, b_events = trace.of(pattern.a), trace.of(pattern.b)
        if a_events and b_events and min(e.time for e in a_events) < max(e.time for e in b_events):
            return TRUE
        return FALSE  # both live, but no a-before-b ordering observed

    if isinstance(pattern, Any):
        acc = FALSE  # ∃-detect identity
        for p in pattern.parts:
            acc = tjoin(acc, recognize(p, trace))
        return acc

    if isinstance(pattern, All):
        acc = TRUE  # ∀-validate identity
        for p in pattern.parts:
            acc = tmeet(acc, recognize(p, trace))
        return acc

    if isinstance(pattern, Never):
        return neg(recognize(pattern.inner, trace))  # the seam: NONE-preserving by neg

    raise TypeError(f"unknown pattern: {type(pattern).__name__}")
