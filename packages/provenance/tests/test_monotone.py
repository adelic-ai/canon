"""Tests for the monotonicity gate itself — the acceptance test for a fold.

The gate is reusable infrastructure every future fold's test imports, so it must catch a
non-monotone map, not just pass the carrier's own ops. We check both directions: genuine
folds pass; a deliberately knowledge-losing map fails.
"""
import pytest

from provenance import (
    ALL,
    BOTH,
    FALSE,
    NONE,
    TRUE,
    Four,
    assert_k_monotone,
    is_k_monotone_binary,
    is_k_monotone_unary,
    kjoin,
    neg,
)


def test_identity_is_monotone():
    assert is_k_monotone_unary(lambda a: a)


def test_constant_is_monotone():
    assert is_k_monotone_unary(lambda a: TRUE)


def test_gate_catches_non_monotone_unary():
    # Maps BOTH (knowledge top) down to NONE (bottom) -> loses knowledge -> not monotone.
    drop_top = lambda a: NONE if a is BOTH else a  # noqa: E731
    assert not is_k_monotone_unary(drop_top)


def test_gate_catches_non_monotone_binary():
    # Ignores its args except to collapse the top case -> non-monotone in both coords.
    bad = lambda a, b: NONE if (a is BOTH or b is BOTH) else TRUE  # noqa: E731
    assert not is_k_monotone_binary(bad)


def test_assert_passes_for_real_fold():
    assert_k_monotone(neg, arity=1)
    assert_k_monotone(kjoin, arity=2)


def test_assert_raises_for_non_monotone():
    drop_top = lambda a: NONE if a is BOTH else a  # noqa: E731
    with pytest.raises(AssertionError):
        assert_k_monotone(drop_top, arity=1)


def test_assert_rejects_bad_arity():
    with pytest.raises(ValueError):
        assert_k_monotone(neg, arity=3)
