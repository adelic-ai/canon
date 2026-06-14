"""Real-data validation — cloudtrail_region_sweep on the flaws.cloud corpus.

The first non-synthetic check: a PROPER detector (untuned) on REAL AWS CloudTrail it never saw. The
corpus contains real opportunistic attacker activity — a leaked `backup` IAM user resource-hijacking
(RunInstances / CreateDefaultVpc / DescribeSpotPriceHistory across all 15 regions, ATT&CK T1496) —
alongside benign actors, including security scanners (Security Monkey / CloudAux / CloudSploit) that
also touch many regions. The load-bearing result: the conformal-entropy detector flags ONLY the
attacker, not the benign multi-region scanners — structure earning precision over a naive
"fires-on-multi-region" baseline, on real data.

Corpus: ~/data/flaws-cloudtrail/v1/ (see its manifest.md). Uses file 00 (uncompressed, 100k records).
"""

from pathlib import Path

import pytest

from detection.cloudtrail import CLOUDTRAIL_REGION_SWEEP, load_cloudtrail_events
from detection.fanout import fanout_verdicts, run_binding

CORPUS = Path.home() / "data/flaws-cloudtrail/v1/flaws_cloudtrail00.json"
pytestmark = pytest.mark.skipif(not CORPUS.exists(), reason="flaws-cloudtrail corpus not present")


@pytest.fixture(scope="module")
def detection():
    return run_binding(str(CORPUS), CLOUDTRAIL_REGION_SWEEP, loader=load_cloudtrail_events)


def test_region_sweep_flags_only_the_real_attacker(detection):
    flagged = {d.cell.entity for d in detection["detected"]}
    assert flagged == {"backup"}   # the leaked-credential attacker, and only it (1 of 20 actors)


def test_benign_multiregion_scanners_not_flagged(detection):
    # these touch ~14 regions too, but legitimately (security scanning) → must NOT be flagged
    flagged = {d.cell.entity for d in detection["detected"]}
    for benign in ("secmonkey", "cloudaux", "cloudsploit_scan", "AWSService"):
        assert benign not in flagged


def test_emits_canonical_t1496_verdicts(detection):
    verdicts = fanout_verdicts(detection)
    assert verdicts
    for v in verdicts:
        contract = v.to_contract()
        assert contract["technique"] == "T1496"      # Resource Hijacking
        assert contract["custody"] == "none"          # unsigned corpus — not faked
