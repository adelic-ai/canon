"""Subgraph-pattern detection on OTRF — the structural LSASS-dump detector, promoted to proper.

The precise two-motif subgraph (comsvcs spawn ∧ lsass VM_READ, joined at the process GUID) finds the
one real dump; the single-motif surfacer is broader. Emits canonical verdicts with no calibrated FAR.
"""

from pathlib import Path

import pytest

from detection.registry import run_applicable
from detection.subgraph import LSASS_READ_ANY, load_sysmon_events, lsass_dump_verdicts, pattern_verdicts

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
pytestmark = pytest.mark.skipif(not OTRF.exists(), reason="OTRF LSASS corpus not present")


@pytest.fixture(scope="module")
def verdicts():
    return lsass_dump_verdicts(str(OTRF))


def test_finds_the_comsvcs_dump(verdicts):
    assert len(verdicts) == 1                              # the precise subgraph isolates the one dump
    c = verdicts[0].to_contract()
    assert c["technique"] == "T1003.001"
    assert c["decision"] == "true"


def test_surfacer_is_broader_than_the_subgraph():
    ev = load_sysmon_events(str(OTRF))
    assert len(pattern_verdicts(LSASS_READ_ANY, ev)) > 1  # the single-motif net catches more readers


def test_structural_verdict_is_uncalibrated_well_formed(verdicts):
    c = verdicts[0].to_contract()
    assert c["guarantee"]["tier"] == "well_formed"        # earned via SHACL (generic + domain shape)
    assert c.get("calibration") is None                   # structural match — no calibrated FAR
    assert c["custody"] == "none"


def test_registry_gates_lsass_to_sysmon():
    fired, skipped = run_applicable(str(OTRF))
    assert "T1003.001" in {v.to_contract()["technique"] for v in fired}   # fires on Sysmon JSONL
    assert any("cloudtrail_region_sweep" in s for s in skipped)            # non-Sysmon detectors gated out
