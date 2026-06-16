"""Generalized panel — logsource selection beyond category, and entity-level (multi-event) corroboration.

Uses the real SigmaHQ corpus but synthetic events (no large telemetry load): the panel selects
aws/cloudtrail rules by product+service, scores a *set* of events (fire-if-any), and honestly reports
UNCORROBORATED where SigmaHQ's rules don't overlap our detector's event family.
"""

from pathlib import Path

import pytest

from detection.sigma_panel import SIGMA, corroborate
from provenance import NONE, TRUE

pytestmark = pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")

AWS = {"product": "aws", "service": "cloudtrail"}


def test_logsource_selector_by_product_service():
    # T1580: the deduped aws/cloudtrail enum-buckets rule fires on a native CloudTrail ListBuckets event
    r = corroborate("T1580", {"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"}, AWS)
    assert r["belnap"] == TRUE
    assert any("enum_buckets" in n for n in (name for name, _f, _n in r["fired"]))


def test_entity_level_fire_if_any():
    # a flagged entity's event stream: a class fires if ANY event matches (entity-level corroboration)
    events = [{"eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com"},
              {"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"}]
    assert corroborate("T1580", events, AWS)["belnap"] == TRUE


def test_honest_uncorroborated_when_no_family_overlap():
    # T1098 aws rules are evaluable but cover different IAM ops (UpdateLoginProfile, Route53) than our
    # CreateUser/CreateAccessKey family — the panel evaluates and honestly does NOT corroborate
    r = corroborate("T1098", {"eventName": "CreateUser", "eventSource": "iam.amazonaws.com"}, AWS)
    assert r["evaluated"] >= 1          # rules ran (not a silent skip)
    assert r["votes"] == 0
    assert r["belnap"] == NONE
    assert "UNCORROBORATED" in r["verdict"]


def test_category_string_still_works():
    # back-compat: a bare string logsource is still read as a category match
    r = corroborate("T1003.001", {"EventID": "10"}, "process_access")
    assert "classes" in r and r["relevant"] >= 1
