"""Corroboration coverage map — the honest per-detector spectrum, with named gap reasons.

`coverage_category` is a pure classifier (no data). The map itself is exercised against the real
SigmaHQ corpus on synthetic representative events, asserting the spectrum: corroborated where a
community class fires, and a *distinct named reason* (no-overlap / no-same-logsource) where it doesn't.
"""

import pytest

from detection.sigma_panel import SIGMA, corroboration_coverage, coverage_category

pytestmark = pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")

AWS = {"product": "aws", "service": "cloudtrail"}
SEC = {"product": "windows", "service": "security"}


def test_coverage_category_classifier():
    assert coverage_category({"votes": 2, "relevant": 3, "evaluated": 3}) == "CORROBORATED"
    assert coverage_category({"votes": 0, "relevant": 0, "evaluated": 0}) == "no-same-logsource"
    assert coverage_category({"votes": 0, "relevant": 4, "evaluated": 0}) == "not-evaluable"
    assert coverage_category({"votes": 0, "relevant": 4, "evaluated": 2}) == "no-overlap"


def test_coverage_spectrum_on_real_corpus():
    specs = [
        {"technique": "T1580", "logsource": AWS,
         "events": {"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"}},
        {"technique": "T1098", "logsource": AWS,
         "events": {"eventName": "CreateUser", "eventSource": "iam.amazonaws.com"}},
        {"technique": "T1110.003", "logsource": SEC, "events": {"EventID": 4625}},
    ]
    by_tech = {r["technique"]: r for r in corroboration_coverage(specs)}
    assert by_tech["T1580"]["category"] == "CORROBORATED"          # a community class fires
    assert by_tech["T1580"]["fired"]                                # the firing rule is recorded
    assert by_tech["T1098"]["category"] == "no-overlap"            # rules ran, none matched our family
    assert by_tech["T1110.003"]["category"] == "no-same-logsource"  # nothing tagged at all
