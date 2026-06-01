"""Validity-fold tests — source well-formedness, and what a failure means for the chain.

Covers the verdict type (carrying the deviation), the ≤_k-monotone integrity-evidence map, and
the trustworthiness coupling whose headline is: intact custody + malformed content = BOTH (the
soundness alarm), while valid content vindicates nothing.
"""
import pytest

from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    UNCHECKED,
    VALID,
    Validity,
    is_k_monotone_unary,
    malformed,
    trustworthiness,
)
from provenance.validity import _as_integrity_evidence


# ── the verdict type ──────────────────────────────────────────────────────────────────
def test_singletons():
    assert VALID.verdict is TRUE and VALID.deviation == ()
    assert UNCHECKED.verdict is NONE  # absence of a check is NONE, never TRUE
    assert UNCHECKED.deviation == ()


def test_malformed_carries_the_deviation():
    # The deviation is the detection feature, not just a flag — same as "NONE carries what's missing".
    v = malformed("byte length 12 not a multiple of 8 — truncated float64 stream")
    assert v.verdict is FALSE
    assert v.deviation == ("byte length 12 not a multiple of 8 — truncated float64 stream",)


# ── the integrity-evidence map is ≤_k-monotone (the universal invariant) ──────────────
def test_integrity_evidence_is_k_monotone():
    assert is_k_monotone_unary(_as_integrity_evidence)


def test_integrity_evidence_values():
    assert _as_integrity_evidence(TRUE) is NONE  # valid content vindicates nothing
    assert _as_integrity_evidence(NONE) is NONE  # unchecked adds no info
    assert _as_integrity_evidence(FALSE) is FALSE  # malformed contests
    assert _as_integrity_evidence(BOTH) is FALSE  # contradictory validity still contests


# ── the trustworthiness coupling ──────────────────────────────────────────────────────
def test_intact_custody_plus_valid_is_true():
    assert trustworthiness(TRUE, VALID) is TRUE


def test_intact_custody_plus_malformed_is_both_the_soundness_alarm():
    # The headline: faithfully delivered (digest matched) yet bunk -> contradiction -> BOTH.
    assert trustworthiness(TRUE, malformed("bad schema")) is BOTH


def test_intact_custody_plus_unchecked_is_true():
    # No validity check ran; custody alone stands. (Backward-compatible default.)
    assert trustworthiness(TRUE, UNCHECKED) is TRUE


def test_tampered_custody_is_absorbing():
    # Proven in-transit tamper stays FALSE regardless of how valid the (substituted) content is.
    assert trustworthiness(FALSE, VALID) is FALSE
    assert trustworthiness(FALSE, malformed("x")) is FALSE


def test_silent_custody_plus_malformed_is_false_not_both():
    # No positive integrity signal (custody NONE), one negative (malformed) -> FALSE, not BOTH.
    assert trustworthiness(NONE, malformed("x")) is FALSE


def test_valid_content_cannot_vindicate_custody():
    # valid-but-tampered is real: a clean parse must not lift silent/unknown custody to TRUE.
    assert trustworthiness(NONE, VALID) is NONE


@pytest.mark.parametrize("custody", [NONE, TRUE, FALSE, BOTH])
def test_trustworthiness_k_monotone_in_validity(custody):
    # A malformed payload only ever ADDS knowledge over a valid one: it contributes a
    # told-false bit (never a told-true one), and kjoin only sets bits. So in the KNOWLEDGE
    # order bunk >=_k clean — never less. (This is the ≤_k-monotonicity in the validity
    # argument; whether that added knowledge reads as "less trustworthy" is the orthogonal
    # truth order, deliberately not asserted here.)
    clean = trustworthiness(custody, VALID)
    bunk = trustworthiness(custody, malformed("x"))
    from provenance import leq_k
    assert leq_k(clean, bunk)  # bunk knows at least as much (more is told)
