"""Cloud enumeration detector on real flaws.cloud data.

CSAT's entropy-over-recon-channels detector, rebuilt as a canon fan-out binding (entity=principal,
value=eventName, restricted to the discovery API family) so it gains a conformal FAR bound. On flaws
it flags the principal running exhaustive environment + IAM reconnaissance (Level6: all 20 discovery
APIs in bursts). Conformal + 5-min grain is deliberately selective — it catches the bursty recon, not
every identity that ever issued a Describe/List.

(The credential-access counterpart was built as the same fan-out and removed: entropy over IAM-API
diversity flags the legit admin `root` — see detection/cloudtrail.py. Credential-access wants a
rarity detector, not entropy.)

Corpus: ~/data/flaws-cloudtrail/v1/ (file 00, 100k records).
"""

from pathlib import Path

import pytest

from detection.cloudtrail import CLOUDTRAIL_ENUMERATION, load_discovery_events
from detection.fanout import fanout_verdicts, run_binding

CORPUS = Path.home() / "data/flaws-cloudtrail/v1/flaws_cloudtrail00.json"
pytestmark = pytest.mark.skipif(not CORPUS.exists(), reason="flaws-cloudtrail corpus not present")


@pytest.fixture(scope="module")
def detection():
    return run_binding(str(CORPUS), CLOUDTRAIL_ENUMERATION, loader=load_discovery_events)


def test_flags_the_recon_burst(detection):
    flagged = {d.cell.entity for d in detection["detected"]}
    assert "Level6" in flagged          # exhaustive IAM + infra recon across all 20 discovery APIs


def test_is_selective(detection):
    # conformal + 5-min grain is conservative: it does NOT flag every identity that did discovery
    flagged = {d.cell.entity for d in detection["detected"]}
    assert len(flagged) <= 3            # high-precision (was exactly {Level6} at build)


def test_emits_canonical_t1580_verdicts(detection):
    verdicts = fanout_verdicts(detection)
    assert verdicts
    for v in verdicts:
        contract = v.to_contract()
        assert contract["technique"] == "T1580"   # Cloud Infrastructure Discovery
        assert contract["custody"] == "none"        # unsigned corpus — not faked
