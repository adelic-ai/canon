"""The carrier — Belnap's four-valued bilattice, ``FOUR``.

The value domain every fold computes in. Pinned contract:
``contracts/carrier.md`` (read it first); architecture spine §5.

A value is a pair ``(t, f)`` of independent bits — ``t`` = "told true" (some source
asserts it), ``f`` = "told false". The four values and the two partial orders fall out
of that pair:

* ``NONE = (0,0)`` no information (knowledge bottom)
* ``TRUE = (1,0)``
* ``FALSE = (0,1)``
* ``BOTH = (1,1)`` contradictory information (knowledge top)

Two orders, deliberately *not* interchangeable (mixing them is a subtle, real bug, so
they have distinct names here):

* **knowledge** ``leq_k`` — componentwise ``<=`` on ``(t, f)``. ``NONE`` bottom, ``BOTH``
  top. **Every fold must be monotone in this order** (the universal invariant). The two
  knowledge ops:
    - :func:`kjoin` (``⊕``) — accumulate evidence (componentwise OR).
    - :func:`kmeet` (``⊗``) — consensus (componentwise AND).
* **truth** ``leq_t`` — ``t`` up, ``f`` down. ``FALSE`` bottom, ``TRUE`` top. Used *only*
  at the final detect/validate projection. The two truth ops:
    - :func:`tjoin` (``∨``) — OR; ∃-detect.
    - :func:`tmeet` (``∧``) — AND; ∀-validate.

:func:`neg` (``¬``) swaps the pair. It is ``leq_k``-monotone (so it satisfies the
universal invariant) and ``leq_t``-antitone (as a negation should be).

Zero deps, by design: this is bottom-of-stack and the whole point is that any binding
that matches the ``(t, f)`` model reproduces these tables exactly.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Four:
    """A Belnap value as a ``(t, f)`` bit pair. Immutable; equality/hash by the pair.

    Construct via the module singletons :data:`NONE`, :data:`TRUE`, :data:`FALSE`,
    :data:`BOTH` rather than instantiating directly; :func:`from_pair` maps a raw pair
    back to the canonical singleton.
    """

    t: int  # told-true bit (0 or 1)
    f: int  # told-false bit (0 or 1)

    def __post_init__(self) -> None:
        if self.t not in (0, 1) or self.f not in (0, 1):
            raise ValueError(f"Four bits must be 0/1, got (t={self.t!r}, f={self.f!r})")

    def __repr__(self) -> str:  # NONE/TRUE/FALSE/BOTH, not Four(t=…, f=…)
        return _NAMES[(self.t, self.f)]

    # `~a` is negation; the binary order-ops are named functions (NOT dunders) so the
    # knowledge/truth distinction is never blurred by operator overloading.
    def __invert__(self) -> "Four":
        return neg(self)


# ── the four values ────────────────────────────────────────────────────────────────
NONE = Four(0, 0)
TRUE = Four(1, 0)
FALSE = Four(0, 1)
BOTH = Four(1, 1)

#: All four values, in no significant order. The finite domain folds are tested over.
ALL: tuple[Four, ...] = (NONE, TRUE, FALSE, BOTH)

_NAMES = {(0, 0): "NONE", (1, 0): "TRUE", (0, 1): "FALSE", (1, 1): "BOTH"}


def from_pair(t: int, f: int) -> Four:
    """Map a raw ``(t, f)`` pair to the canonical singleton."""
    return {(0, 0): NONE, (1, 0): TRUE, (0, 1): FALSE, (1, 1): BOTH}[(t, f)]


# ── the two orders ───────────────────────────────────────────────────────────────────
def leq_k(a: Four, b: Four) -> bool:
    """Knowledge order: ``a <= b`` iff ``b`` knows at least as much (componentwise)."""
    return a.t <= b.t and a.f <= b.f


def leq_t(a: Four, b: Four) -> bool:
    """Truth order: ``t`` up, ``f`` down — ``a <= b`` iff ``a.t<=b.t`` and ``a.f>=b.f``."""
    return a.t <= b.t and a.f >= b.f


# ── knowledge-order operations (the evidence combiners) ───────────────────────────────
def kjoin(a: Four, b: Four) -> Four:
    """``⊕`` knowledge join — accumulate evidence (componentwise OR).

    ``NONE`` identity, ``BOTH`` absorbing; ``TRUE ⊕ FALSE = BOTH`` (disagreement is a
    contradiction, *not* an average).
    """
    return from_pair(a.t | b.t, a.f | b.f)


def kmeet(a: Four, b: Four) -> Four:
    """``⊗`` knowledge meet — consensus (componentwise AND).

    ``BOTH`` identity, ``NONE`` absorbing; ``TRUE ⊗ FALSE = NONE`` (no agreement, no
    knowledge).
    """
    return from_pair(a.t & b.t, a.f & b.f)


# ── truth-order operations (the detect/validate projection) ───────────────────────────
def tjoin(a: Four, b: Four) -> Four:
    """``∨`` truth join — OR (``t``: OR, ``f``: AND). ``FALSE`` identity. ∃-detect."""
    return from_pair(a.t | b.t, a.f & b.f)


def tmeet(a: Four, b: Four) -> Four:
    """``∧`` truth meet — AND (``t``: AND, ``f``: OR). ``TRUE`` identity. ∀-validate."""
    return from_pair(a.t & b.t, a.f | b.f)


# ── negation ──────────────────────────────────────────────────────────────────────────
def neg(a: Four) -> Four:
    """``¬`` — swap the pair. Fixes ``NONE``/``BOTH``, flips ``TRUE``/``FALSE``.

    ``leq_k``-monotone (satisfies the universal invariant) and ``leq_t``-antitone.
    """
    return from_pair(a.f, a.t)
