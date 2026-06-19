"""Vocabulary descriptor + coherence gate — the OFF-able seam for OCSF normalization.

`native` is the identity setting (default): the gate is a no-op and the existing native-Sigma
round is unchanged. A mismatched (events, rules) vocabulary pair is refused loudly, before
firing — so it's an error, not a silent all-NONE round.
"""

import pytest

from detection.vocab import (
    NATIVE,
    OCSF,
    Vocabulary,
    VocabularyMismatch,
    coheres,
    require_coherent,
    vocab_name,
)


def test_native_default_coheres_with_itself():
    assert coheres(NATIVE, NATIVE)
    require_coherent(NATIVE, NATIVE)            # no raise — identity setting


def test_mismatched_pair_is_refused():
    assert not coheres(NATIVE, OCSF)
    with pytest.raises(VocabularyMismatch):
        require_coherent(OCSF, NATIVE)          # ocsf rules vs native events would silently miss


def test_vocabulary_name_and_schema():
    v = Vocabulary(OCSF, schema="ocsf-1.3")
    assert vocab_name(v) == OCSF                # coherence is judged on name, not schema
    assert str(v) == "ocsf(ocsf-1.3)"
    assert coheres(v, OCSF)                     # a schema-pinned ocsf coheres with bare ocsf
    assert vocab_name("native") == "native"     # bare strings pass through


def test_round_refuses_mismatch_before_touching_the_corpus():
    """The guard fires before any rule gathering, so a mismatch raises even with no events and
    no Sigma corpus present — a pure-logic check, no fixtures needed."""
    from detection.round import evaluate_round

    with pytest.raises(VocabularyMismatch):
        evaluate_round([], ["T1003.001"], events_vocab=OCSF, rules_vocab=NATIVE, use_rust=False)
