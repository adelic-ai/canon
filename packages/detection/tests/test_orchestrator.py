"""Orchestrator — fire → map to tactic → project the forward frontier from the learned model.

Needs both corpora: faker-kerberos (the event stream to detect over) and attack-flow-corpus (to learn
the transition model). The load-bearing assertion is the chained walk: on faker, credential-access is
confirmed AND the model's strongest forward edge (credential-access → lateral-movement) is COVERED,
because the pass-the-ticket detector is applicable to this corpus.
"""

from pathlib import Path

import pytest

from detection.killchain import build_model
from detection.orchestrator import COVERED, orchestrate

FAKER = str(Path.home() / "data/faker-kerberos/v1/export.csv")
CORPUS = Path.home() / "data/attack-flow-corpus"
pytestmark = pytest.mark.skipif(
    not (Path(FAKER).exists() and CORPUS.exists()), reason="corpora not present"
)


def test_confirms_milestones_and_chains_to_lateral_movement():
    transitions, *_ = build_model(CORPUS)
    r = orchestrate(FAKER, transitions)
    assert "credential-access" in r["observed"]
    assert "lateral-movement" in r["observed"]
    cred_lat = [f for f in r["frontier"]
                if f[0] == "credential-access" and f[1] == "lateral-movement"]
    assert cred_lat and cred_lat[0][3] == COVERED   # the 43% edge is verifiable here


def test_orchestrate_with_hmm_still_confirms_milestones():
    # opt-in HMM path: gated decode refines the observed tactics but, because faker's fan-out techniques
    # are single-tactic (kerberoast → credential-access, pass-the-ticket → lateral-movement), the gate is
    # additive here — the milestones still confirm (no regression from turning the HMM on).
    from detection.hmm import emission_model
    transitions, starts, *_ = build_model(CORPUS)
    r = orchestrate(FAKER, transitions, emissions=emission_model(CORPUS), starts=starts)
    assert "credential-access" in r["observed"]
    assert "lateral-movement" in r["observed"]


def test_frontier_statuses_are_well_formed():
    transitions, *_ = build_model(CORPUS)
    r = orchestrate(FAKER, transitions)
    assert r["frontier"]
    assert {f[3] for f in r["frontier"]} <= {"covered", "observability-gap", "coverage-gap"}
    # probabilities are descending within each from-tactic (best-first ordering)
    by_from: dict[str, list[float]] = {}
    for ft, _nt, p, _s, _d in r["frontier"]:
        by_from.setdefault(ft, []).append(p)
    for probs in by_from.values():
        assert probs == sorted(probs, reverse=True)
