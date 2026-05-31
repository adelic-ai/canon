"""The ``leq_k``-monotonicity gate — *the* acceptance test for a fold.

``fold_protocol.md`` req 2 / ``carrier.md`` "universal invariant": every fold must be
``leq_k``-monotone — feeding a child more knowledge may only move the result *up* the
knowledge order, never down. This module is the reusable checker every fold's test imports
so "add concern N without touching concern M" is verified, not asserted.

The carrier is finite (four values), so monotonicity is checked **exhaustively** over the
whole domain (and, for binary ops, the whole product) — a complete proof, not a sample.
That is why no property-based-testing dependency is needed for the core invariant.
"""

from __future__ import annotations

from itertools import product
from typing import Callable

from provenance.carrier import ALL, Four, leq_k


def is_k_monotone_unary(fn: Callable[[Four], Four]) -> bool:
    """True iff ``a leq_k b  ⇒  fn(a) leq_k fn(b)`` for all of the four values."""
    return all(
        leq_k(fn(a), fn(b))
        for a in ALL
        for b in ALL
        if leq_k(a, b)
    )


def is_k_monotone_binary(fn: Callable[[Four, Four], Four]) -> bool:
    """True iff ``fn`` is ``leq_k``-monotone in *both* arguments, exhaustively.

    Checks monotonicity in each coordinate over the full ``ALL × ALL`` product: raising
    one argument up ``leq_k`` (holding the other fixed) may only raise the result.
    """
    left = all(
        leq_k(fn(a, c), fn(b, c))
        for a, b, c in product(ALL, ALL, ALL)
        if leq_k(a, b)
    )
    right = all(
        leq_k(fn(c, a), fn(c, b))
        for a, b, c in product(ALL, ALL, ALL)
        if leq_k(a, b)
    )
    return left and right


def assert_k_monotone(fn: Callable, *, arity: int) -> None:
    """Raise ``AssertionError`` if ``fn`` is not ``leq_k``-monotone. CI-gate form.

    ``arity`` is 1 or 2. A fold of higher arity should be checked by currying it down to
    one moving argument at a time and calling this per argument.
    """
    if arity == 1:
        ok = is_k_monotone_unary(fn)
    elif arity == 2:
        ok = is_k_monotone_binary(fn)
    else:
        raise ValueError(f"arity must be 1 or 2, got {arity!r}")
    if not ok:
        raise AssertionError(
            f"{getattr(fn, '__name__', fn)!r} is NOT leq_k-monotone "
            f"(arity {arity}) — it violates the universal fold invariant"
        )
