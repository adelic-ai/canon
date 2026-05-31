"""Temporal-fold tests — chronicle recognition + the §6 negation-under-partial-data seam.

The centerpiece is negation: "C never occurred" must be TRUE on a live feed but NONE on a
silent one, with NO special-casing — carrier neg does it. Also covers leaves, windows,
ordering, the detect/validate duality, and ≤_k-monotonicity in the feed.
"""
import pytest

from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    All,
    Any,
    Before,
    Event,
    Never,
    Occurs,
    Trace,
    Window,
    recognize,
)


def _trace(events, live):
    return Trace(events=tuple(events), live=frozenset(live))


A = Event("A", 1.0)
B = Event("B", 2.0)


# ── leaves: the liveness rule ───────────────────────────────────────────────────────
def test_occurs_present_is_true():
    assert recognize(Occurs("A"), _trace([A], live={"A"})) is TRUE


def test_occurs_absent_on_live_feed_is_false():
    # Feed healthy, event genuinely not there -> confident FALSE.
    assert recognize(Occurs("A"), _trace([B], live={"A", "B"})) is FALSE


def test_occurs_absent_on_silent_feed_is_none():
    # Channel A not live -> absence is unknown, NOT a confident negative.
    assert recognize(Occurs("A"), _trace([B], live={"B"})) is NONE


def test_window_respects_bounds():
    t = _trace([Event("A", 5.0)], live={"A"})
    assert recognize(Window("A", 0.0, 10.0), t) is TRUE
    assert recognize(Window("A", 0.0, 4.0), t) is FALSE  # outside window, feed live
    assert recognize(Window("A", 0.0, 4.0), _trace([Event("A", 5.0)], live=set())) is NONE


# ── ordering ────────────────────────────────────────────────────────────────────────
def test_before_true_when_ordered():
    assert recognize(Before("A", "B"), _trace([A, B], live={"A", "B"})) is TRUE


def test_before_false_when_misordered_and_live():
    # B before A, both feeds live -> the A-before-B sequence genuinely did not happen.
    assert recognize(Before("A", "B"), _trace([Event("A", 9.0), Event("B", 1.0)], live={"A", "B"})) is FALSE


def test_before_none_when_a_channel_silent():
    assert recognize(Before("A", "B"), _trace([A, B], live={"A"})) is NONE  # B feed silent


# ── the §6 seam: negation under partial data ────────────────────────────────────────
def test_never_true_when_absent_and_live():
    # "C never occurred" with C's feed healthy and no C -> TRUE.
    assert recognize(Never(Occurs("C")), _trace([A], live={"A", "C"})) is TRUE


def test_never_none_when_absent_and_silent():
    # THE trap: C's feed is silent, so we CANNOT claim C never occurred -> NONE, not TRUE.
    assert recognize(Never(Occurs("C")), _trace([A], live={"A"})) is NONE


def test_never_false_when_present():
    assert recognize(Never(Occurs("A")), _trace([A], live={"A"})) is FALSE


# ── detect/validate duality (one pattern tree, two reads) ───────────────────────────
def test_any_is_exists_detect():
    t = _trace([A], live={"A", "B"})  # A present, B genuinely absent
    assert recognize(Any((Occurs("A"), Occurs("B"))), t) is TRUE  # some path matched
    assert recognize(Any(()), t) is FALSE  # ∃-detect identity


def test_all_is_forall_validate():
    t = _trace([A], live={"A", "B"})  # A present, B absent (live -> FALSE)
    assert recognize(All((Occurs("A"), Occurs("B"))), t) is FALSE  # not all held
    assert recognize(All((Occurs("A"),)), t) is TRUE
    assert recognize(All(()), t) is TRUE  # ∀-validate identity


def test_detect_validate_conflict_is_both():
    # Construct a node where ∃-detect says TRUE and ∀-validate (negated) says the opposite,
    # fused -> BOTH (the soundness alarm). A present (TRUE), Never(A) (FALSE) -> Any over
    # {detect=TRUE, validate-view=FALSE} via the carrier yields BOTH on tjoin? No: model the
    # disagreement directly as kjoin of the two path verdicts.
    from provenance import kjoin
    t = _trace([A], live={"A"})
    detect = recognize(Occurs("A"), t)        # TRUE
    validate = recognize(Never(Occurs("A")), t)  # FALSE
    assert kjoin(detect, validate) is BOTH  # confident disagreement -> contradiction


# ── ≤_k-monotonicity in the feed ────────────────────────────────────────────────────
def test_bringing_feed_live_only_raises_knowledge():
    # Silent A (NONE) -> live A with A absent (FALSE): NONE ≤_k FALSE, knowledge rose.
    silent = recognize(Occurs("A"), _trace([B], live={"B"}))
    live = recognize(Occurs("A"), _trace([B], live={"A", "B"}))
    assert silent is NONE and live is FALSE  # moved up ≤_k (NONE is bottom)
