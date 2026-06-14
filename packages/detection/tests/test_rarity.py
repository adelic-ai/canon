"""Rarity detector — flag the rare ACTOR for a sensitive action, not the busy admin.

The complement to the entropy fan-out: where the credential-access fan-out flagged the legit owner
`root` (diverse IAM = admin's job), rarity flags the rare doer. On flaws that's the stolen EC2-instance
role manipulating IAM (the instance-credential priv-esc path) — and crucially NOT `root`.
"""

import json
from collections import Counter
from pathlib import Path

import pytest

from detection.cloudtrail import MANIPULATION_APIS, _identity
from detection.rarity import cloud_account_manipulation_verdicts, rare_actors

CORPUS = Path.home() / "data/flaws-cloudtrail/v1/flaws_cloudtrail00.json"
_skip_no_corpus = pytest.mark.skipif(not CORPUS.exists(), reason="flaws-cloudtrail corpus not present")


def test_rare_actors_excludes_dominant_includes_tail():
    # deterministic: the established doer is the baseline; the low-share tail is flagged
    counts = Counter({"root": 36, "Level6": 18, "backup": 11, "piper": 3, "i-abc": 1})
    flagged = {a for a, _, _ in rare_actors(counts, max_share=0.05)}
    assert flagged == {"piper", "i-abc"}           # the <5%-share tail
    assert "root" not in flagged                    # 52% share — the established admin, never flagged


@_skip_no_corpus
def test_flaws_flags_instance_role_not_root():
    recs = json.load(open(CORPUS))["Records"]
    counts = Counter(_identity(e) for e in recs if e.get("eventName") in MANIPULATION_APIS)
    flagged = {a for a, _, _ in rare_actors(counts, max_share=0.05)}
    assert any(a.startswith("i-") for a in flagged)     # stolen EC2-instance role manipulating IAM (TP)
    assert not any("root" in a for a in flagged)         # the established admin is NOT flagged (the goal)


@_skip_no_corpus
def test_detector_emits_uncalibrated_t1098_verdicts():
    verdicts = cloud_account_manipulation_verdicts(str(CORPUS))
    assert verdicts
    for v in verdicts:
        contract = v.to_contract()
        assert contract["technique"] == "T1098"          # Account Manipulation
        assert contract.get("calibration") is None        # rarity has no conformal FAR — honest
