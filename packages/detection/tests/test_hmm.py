"""HMM over the kill chain — emission ambiguity + Viterbi context-disambiguation.

The headline: the SAME multi-tactic technique decodes to DIFFERENT tactics depending on the
surrounding chain — which the 1:1 TECH_TACTIC map cannot do. Plus the honest limitation: a technique
absent from the corpus has no emission, so Viterbi can't help there.
"""

from pathlib import Path

import pytest

from detection.hmm import decode, emission_model, viterbi
from detection.killchain import build_model

CORPUS = Path.home() / "data/attack-flow-corpus"
pytestmark = pytest.mark.skipif(not CORPUS.exists(), reason="attack-flow-corpus not present")


@pytest.fixture(scope="module")
def model():
    transitions, starts, *_ = build_model(CORPUS)
    return transitions, starts, emission_model(CORPUS)


def test_emission_model_learns_multitactic_ambiguity(model):
    *_, B = model
    emitters = {ta for ta, em in B.items() if "T1098" in em}
    assert {"persistence", "priv-esc"} <= emitters   # T1098 is genuinely ambiguous in the data


def test_viterbi_disambiguates_same_technique_by_context(model):
    transitions, starts, B = model
    # SAME ambiguous T1098, different chains → different inferred tactic (impossible for a 1:1 map)
    as_persistence = viterbi(["T1059", "T1098", "T1486"], transitions, B, starts)
    as_privesc = viterbi(["T1003", "T1098", "T1021"], transitions, B, starts)
    assert as_persistence[1] == "persistence"
    assert as_privesc[1] == "priv-esc"
    assert as_persistence[1] != as_privesc[1]        # the headline: context decides, not a hardcode


def test_out_of_corpus_technique_has_no_emission(model):
    # honest limitation: cloud T1580 is absent from the host corpus → no emission → Viterbi can't help
    *_, B = model
    assert not any("T1580" in em for em in B.values())
