"""Orchestrator end-to-end on real cloud data (flaws.cloud).

The whole engine on one real corpus: fire the registry (observability-gated) → map each verdict to its
ATT&CK tactic → project the forward frontier from the learned transition model. On flaws it confirms
THREE kill-chain milestones from THREE different detector primitives — discovery (T1580 enumeration,
entropy fan-out), priv-esc (T1098 account-manipulation, rarity), impact (T1496 region-sweep, entropy
fan-out) — the multi-stage real attack, end to end.

Honest limitation (asserted below as a coverage gap, not hidden): the transition model is learned from
host/enterprise Attack-Flow incidents, so it doesn't rank the cloud discovery→priv-esc→impact
progression as its top forward edges, and canon has no cloud C2/defense-evasion/collection detectors —
so the forward frontier is mostly coverage gaps. The multi-stage *detection* is real; accurate cloud
*forward-prediction* would need a cloud-incident transition model.
"""

from pathlib import Path

import pytest

from detection.killchain import build_model
from detection.orchestrator import orchestrate

FLAWS = Path.home() / "data/flaws-cloudtrail/v1/flaws_cloudtrail00.json"
CORPUS = Path.home() / "data/attack-flow-corpus"
pytestmark = pytest.mark.skipif(
    not (FLAWS.exists() and CORPUS.exists()), reason="corpora not present"
)


@pytest.fixture(scope="module")
def result():
    transitions, *_ = build_model(CORPUS)
    return orchestrate(str(FLAWS), transitions)


def test_confirms_three_cloud_kill_chain_milestones(result):
    assert {"discovery", "priv-esc", "impact"} <= set(result["observed"])


def test_fired_by_three_distinct_detectors(result):
    techniques = {v.technique for v in result["verdicts"]}
    assert {"T1580", "T1098", "T1496"} <= techniques


def test_frontier_flags_cloud_coverage_gaps(result):
    # no cloud C2 / defense-evasion / collection detectors → those forward edges are coverage gaps
    statuses = {f[3] for f in result["frontier"]}
    assert "coverage-gap" in statuses
