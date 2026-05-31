"""Carrier tests — the Belnap bilattice, against the pinned contract.

The contract (``~/canon/contracts/carrier.md``) ships explicit truth tables; these tests
ARE those tables, transcribed, plus the order/law/monotonicity properties. The whole
domain is four values, so every property is checked **exhaustively** (a proof, not a
sample) — no Hypothesis needed.
"""
from itertools import product

import pytest

from provenance import (
    ALL,
    BOTH,
    FALSE,
    NONE,
    TRUE,
    Four,
    from_pair,
    is_k_monotone_binary,
    is_k_monotone_unary,
    kjoin,
    kmeet,
    leq_k,
    leq_t,
    neg,
    tjoin,
    tmeet,
)

# Row/col order shared by every table below (matches carrier.md's tables).
ORDER = (NONE, TRUE, FALSE, BOTH)


def _check_table(op, rows):
    """Assert ``op(r, c)`` equals ``rows[i][j]`` for the ORDER grid."""
    for r, row in zip(ORDER, rows):
        for c, expected in zip(ORDER, row):
            assert op(r, c) is expected, f"{op.__name__}({r}, {c}) = {op(r, c)}, want {expected}"


# ── the values ────────────────────────────────────────────────────────────────────
def test_value_pairs():
    assert (NONE.t, NONE.f) == (0, 0)
    assert (TRUE.t, TRUE.f) == (1, 0)
    assert (FALSE.t, FALSE.f) == (0, 1)
    assert (BOTH.t, BOTH.f) == (1, 1)


def test_repr_is_named():
    assert [repr(v) for v in ORDER] == ["NONE", "TRUE", "FALSE", "BOTH"]


def test_from_pair_returns_singletons():
    for v in ALL:
        assert from_pair(v.t, v.f) is v


def test_bad_bits_rejected():
    with pytest.raises(ValueError):
        Four(2, 0)


# ── orders ────────────────────────────────────────────────────────────────────────
def test_knowledge_order_bottom_top():
    assert all(leq_k(NONE, v) for v in ALL)  # NONE is bottom
    assert all(leq_k(v, BOTH) for v in ALL)  # BOTH is top
    assert not leq_k(TRUE, FALSE) and not leq_k(FALSE, TRUE)  # T, F incomparable


def test_truth_order_bottom_top():
    assert all(leq_t(FALSE, v) for v in ALL)  # FALSE is bottom
    assert all(leq_t(v, TRUE) for v in ALL)  # TRUE is top
    assert not leq_t(NONE, BOTH) and not leq_t(BOTH, NONE)  # NONE, BOTH incomparable


# ── the four operation tables (transcribed from carrier.md) ─────────────────────────
def test_kjoin_table():
    _check_table(kjoin, [
        [NONE,  TRUE,  FALSE, BOTH],
        [TRUE,  TRUE,  BOTH,  BOTH],
        [FALSE, BOTH,  FALSE, BOTH],
        [BOTH,  BOTH,  BOTH,  BOTH],
    ])


def test_kmeet_table():
    _check_table(kmeet, [
        [NONE, NONE,  NONE,  NONE],
        [NONE, TRUE,  NONE,  TRUE],
        [NONE, NONE,  FALSE, FALSE],
        [NONE, TRUE,  FALSE, BOTH],
    ])


def test_tjoin_table():
    _check_table(tjoin, [
        [NONE, TRUE, NONE,  TRUE],
        [TRUE, TRUE, TRUE,  TRUE],
        [NONE, TRUE, FALSE, BOTH],
        [TRUE, TRUE, BOTH,  BOTH],
    ])


def test_tmeet_table():
    _check_table(tmeet, [
        [NONE,  NONE, FALSE, FALSE],
        [NONE,  TRUE, FALSE, BOTH],
        [FALSE, FALSE, FALSE, FALSE],
        [FALSE, BOTH, FALSE, BOTH],
    ])


def test_negation_table():
    assert neg(NONE) is NONE
    assert neg(BOTH) is BOTH
    assert neg(TRUE) is FALSE
    assert neg(FALSE) is TRUE
    assert all(~v is neg(v) for v in ALL)  # __invert__ delegates to neg


# ── the load-bearing facts the contract calls out by name ───────────────────────────
def test_disagreement_is_contradiction_not_average():
    assert kjoin(TRUE, FALSE) is BOTH   # accumulate evidence: disagreement -> Both
    assert kmeet(TRUE, FALSE) is NONE   # consensus: no agreement -> no knowledge


def test_none_is_kjoin_identity_both_is_absorbing():
    assert all(kjoin(NONE, v) is v for v in ALL)
    assert all(kjoin(BOTH, v) is BOTH for v in ALL)


# ── algebraic laws (exhaustive) ─────────────────────────────────────────────────────
@pytest.mark.parametrize("op", [kjoin, kmeet, tjoin, tmeet])
def test_commutative(op):
    assert all(op(a, b) is op(b, a) for a, b in product(ALL, ALL))


@pytest.mark.parametrize("op", [kjoin, kmeet, tjoin, tmeet])
def test_associative(op):
    assert all(
        op(op(a, b), c) is op(a, op(b, c))
        for a, b, c in product(ALL, ALL, ALL)
    )


@pytest.mark.parametrize("op", [kjoin, kmeet, tjoin, tmeet])
def test_idempotent(op):
    assert all(op(a, a) is a for a in ALL)


def test_negation_involutive():
    assert all(neg(neg(a)) is a for a in ALL)


def test_de_morgan_swaps_truth_ops():
    # ¬(a ∨ b) = ¬a ∧ ¬b  and  ¬(a ∧ b) = ¬a ∨ ¬b
    for a, b in product(ALL, ALL):
        assert neg(tjoin(a, b)) is tmeet(neg(a), neg(b))
        assert neg(tmeet(a, b)) is tjoin(neg(a), neg(b))


# ── the universal invariant: every op is leq_k-monotone ─────────────────────────────
@pytest.mark.parametrize("op", [kjoin, kmeet, tjoin, tmeet])
def test_binary_ops_are_k_monotone(op):
    assert is_k_monotone_binary(op)


def test_negation_is_k_monotone():
    assert is_k_monotone_unary(neg)  # ¬ swaps both components -> preserves componentwise <=
