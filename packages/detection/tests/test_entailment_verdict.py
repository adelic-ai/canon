"""Unified entailment verdict — the adapters, and the open-vs-closed-world honesty.

The three entailment mechanisms map into one carrier (CONFIRMED/REFUTED/GAP/NONE).
The load-bearing assertion is that model-checking (closed-world) and DL subsumption
(open-world) DISAGREE on absence: absence refutes a rule but leaves a subsumption
unknown. That asymmetry is why the carrier needs both REFUTED and NONE.
"""

import pytest

from provenance import FALSE as B_FALSE
from provenance import NONE as B_NONE
from provenance import TRUE as B_TRUE

from detection.entailment_verdict import (
    CONFIRMED,
    GAP,
    NONE,
    REFUTED,
    VERDICTS,
    entailment_to_belnap,
    from_gap,
    from_model_check,
    from_subsumption,
)


def test_gap_outcomes_pass_through():
    for o in (CONFIRMED, GAP, NONE):
        assert from_gap(o) == o
    with pytest.raises(ValueError):
        from_gap("REFUTED")                    # the GAP mechanism never refutes


def test_model_check_is_closed_world():
    assert from_model_check(True) == CONFIRMED
    assert from_model_check(False) == REFUTED  # absence refutes a rule


def test_subsumption_is_open_world():
    assert from_subsumption(True) == CONFIRMED
    assert from_subsumption(False) == NONE     # absence is UNKNOWN, NOT refuted


def test_closed_and_open_world_disagree_on_absence():
    # the crux of the unification: the SAME "not present" fact maps two different ways
    assert from_model_check(False) == REFUTED
    assert from_subsumption(False) == NONE
    assert from_model_check(False) != from_subsumption(False)


def test_belnap_projection():
    assert entailment_to_belnap(CONFIRMED) is B_TRUE
    assert entailment_to_belnap(REFUTED) is B_FALSE
    assert entailment_to_belnap(NONE) is B_NONE
    assert entailment_to_belnap(GAP) is B_TRUE     # entailed → it happened; the gap rides as a warrant
    # every carrier verdict projects
    for v in VERDICTS:
        assert entailment_to_belnap(v) in (B_TRUE, B_FALSE, B_NONE)
