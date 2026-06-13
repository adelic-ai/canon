"""Kill-chain transition model — learned from the real Attack-Flow corpus.

The load-bearing, data-backed result is the forward edge: from credential-access the most likely
next milestone is lateral-movement. That's the orchestrator's strongest prior and the consequence-
trigger the cross-check work leans on, so it's the thing worth pinning with a test.
"""

from pathlib import Path

import pytest

from detection.killchain import build_model, forward_nexts

CORPUS = Path.home() / "data/attack-flow-corpus"
pytestmark = pytest.mark.skipif(not CORPUS.exists(), reason="attack-flow-corpus not present")


def test_model_parses_incidents_and_builds_transitions():
    transitions, starts, flows_parsed, n_files = build_model(CORPUS)
    assert flows_parsed > 0
    assert transitions                      # tactic→tactic edges were learned
    assert sum(transitions.values()) > flows_parsed   # multiple transitions per incident


def test_credential_access_leads_to_lateral_movement():
    transitions, *_ = build_model(CORPUS)
    nexts = forward_nexts(transitions)
    assert "credential-access" in nexts
    top_next, prob = nexts["credential-access"][0]
    assert top_next == "lateral-movement"   # the data-backed strongest forward edge
    assert prob > 0.3


def test_forward_nexts_rows_are_normalized():
    transitions, *_ = build_model(CORPUS)
    for row in forward_nexts(transitions).values():
        assert abs(sum(p for _, p in row) - 1.0) < 1e-9
