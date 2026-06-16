"""Sigma corroboration panel — the deduped external second opinion on a canon finding.

The minimal evaluator is a pure unit (no data). The panel test runs against the real SigmaHQ corpus +
OTRF: canon's lsass_dump_subgraph (T1003.001) is independently corroborated by deduped community rules,
the dedup collapses near-duplicates (so corroboration isn't inflated), and a non-evaluable class is
reported NONE rather than silently counted.
"""

from pathlib import Path

import pytest

from detection.sigma_eval import is_evaluable, rule_fires
from detection.sigma_panel import SIGMA, corroborate, lsass_comsvcs_event
from detection.subgraph import load_sysmon_events
from provenance import TRUE

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"


# --- the evaluator: pure unit, no corpus -------------------------------------------------------- #

def test_evaluator_contains_and_endswith():
    rule = {"detection": {"selection": {"Image|endswith": "\\comsvcs.dll",
                                         "CallTrace|contains": "dbghelp"},
                          "condition": "selection"}}
    assert is_evaluable(rule)
    assert rule_fires(rule, {"Image": "C:\\Windows\\System32\\comsvcs.dll",
                             "CallTrace": "... dbghelp.dll+..."})
    assert not rule_fires(rule, {"Image": "C:\\notepad.exe", "CallTrace": "dbghelp"})


def test_evaluator_filter_suppresses():
    rule = {"detection": {"selection": {"TargetImage|endswith": "lsass.exe"},
                          "filter": {"SourceImage|endswith": "wmiprvse.exe"},
                          "condition": "selection and not filter"}}
    assert rule_fires(rule, {"TargetImage": "C:\\lsass.exe", "SourceImage": "evil.exe"})
    assert not rule_fires(rule, {"TargetImage": "C:\\lsass.exe", "SourceImage": "C:\\wmiprvse.exe"})


def test_evaluator_rejects_nested_blocks():
    assert not is_evaluable({"detection": {"selection": {"sub": {"a": 1}}, "condition": "selection"}})


# --- the panel: real SigmaHQ corpus + OTRF ------------------------------------------------------ #

pytestmark_data = pytest.mark.skipif(
    not (OTRF.exists() and SIGMA.exists()), reason="OTRF corpus or SigmaHQ rules not present")


@pytest.fixture(scope="module")
def result():
    ev = lsass_comsvcs_event(load_sysmon_events(str(OTRF)))
    assert ev is not None
    return corroborate("T1003.001", ev, "process_access")


@pytestmark_data
def test_canon_finding_is_corroborated(result):
    assert result["votes"] >= 1
    assert result["belnap"] == TRUE


@pytestmark_data
def test_dedup_collapses_near_duplicates(result):
    # counting raw rules would overstate corroboration — the FCA dedup is the point
    assert result["classes"] < result["relevant"]


@pytestmark_data
def test_the_dedicated_comsvcs_rule_fires(result):
    names = [name for name, _fields, _n in result["fired"]]
    assert any("comsvcs" in n for n in names)   # SigmaHQ catches comsvcs via CallTrace


@pytestmark_data
def test_non_evaluable_class_is_none_not_a_no_vote(result):
    # a class the minimal evaluator can't run is reported, not silently counted as a non-firing vote
    assert result["evaluated"] + len(result["skipped"]) == result["classes"]
