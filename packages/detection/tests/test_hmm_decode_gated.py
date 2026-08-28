"""`decode_gated`'s empty-emissions guard — corpus-independent, so no `attack-flow-corpus` fixture
needed (unlike `test_hmm.py`, which is skipped without it). Regression for: a totally unsupported
HMM model (`emissions == {}`) used to reach `viterbi`'s `max(states, ...)` on an empty state list
and raise `ValueError` instead of degrading to the 1:1 fallback map."""
from collections import Counter

from detection.hmm import decode_gated


def test_empty_emissions_falls_back_instead_of_crashing():
    fallback = {"T1003": "credential-access", "T1098": "persistence"}
    out = decode_gated(
        ["T1003", "T1098"],
        fallback=fallback,
        transitions=Counter(),
        starts=Counter(),
        emissions={},
    )
    assert out == ["credential-access", "persistence"]


def test_empty_emissions_with_no_fallback_entry_passes_the_observation_through():
    out = decode_gated(
        ["T9999"], fallback={}, transitions=Counter(), starts=Counter(), emissions={},
    )
    assert out == ["T9999"]


def test_empty_emissions_and_empty_observations_returns_empty():
    assert decode_gated([], fallback={}, transitions=Counter(), starts=Counter(), emissions={}) == []


def test_single_state_model_still_decodes():
    transitions = Counter({("a", "a"): 1})
    starts = Counter({"a": 1})
    emissions = {"a": {"T1": 1.0}}
    out = decode_gated(["T1"], fallback={}, transitions=transitions, starts=starts, emissions=emissions)
    assert out == ["a"]
