"""Sigma consumption pass — classify (with reasons) + FCA-dedup the corpus.

A synthetic mini-corpus pins the mechanics (reasons, FCA dedup, technique coverage); the real-corpus test
(gated on the vendored Sigma rules) runs the actual consumption and asserts the report is internally
consistent — that run produces the live scorecard.
"""

from pathlib import Path

import pytest
import yaml

from detection.audit import consume_sigma
from detection.sigma_eval import evaluability
from detection.sigma_panel import SIGMA


def test_evaluability_attributes_each_reason():
    def rule(**det):
        return {"detection": det}
    assert evaluability(rule(selection={"a|endswith": "x"}, condition="selection")) == (True, "ok")
    # the condition parser now compiles named-block boolean/quantifier conditions → ok (the coverage win)
    assert evaluability(rule(selection={"a": "x"}, condition="1 of selection*")) == (True, "ok")
    assert evaluability(rule(s1={"a": "x"}, s2={"b": "y"}, condition="s1 and not s2")) == (True, "ok")
    assert evaluability(rule(selection={"a": "x"}, condition="selection | count() by b > 5"))[1] == "aggregation"
    assert evaluability(rule(selection={"a": "x"}, condition="selection and"))[1] == "condition-unsupported"
    assert evaluability(rule(selection={"a": {"nested": 1}}, condition="selection"))[1] == "nested-selection"
    assert evaluability(rule(keywords=["foo", "bar"], condition="keywords")) == (True, "ok")   # keyword block now compiles
    assert evaluability(rule(weird=None, condition="weird"))[1] == "unsupported-block"          # None block: not yet
    assert evaluability(rule(selection={"a|re": ".*x"}, condition="selection"))[1] == "unsupported-modifier"  # |re abstains, not mis-fires
    assert evaluability({"correlation": {"type": "event_count"}})[1] == "correlation"
    assert evaluability({"title": "no detection"})[1] == "no-detection"


def _write(dirp: Path, name: str, rule: dict):
    (dirp / name).write_text(yaml.safe_dump(rule))


def test_consume_dedups_and_classifies_a_mini_corpus(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    # two evaluable rules with the SAME signature (process_access, field-set {TargetImage}) → one FCA class
    _write(d, "a.yml", {"id": "a", "logsource": {"product": "windows", "category": "process_access"},
                        "detection": {"selection": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "selection"},
                        "tags": ["attack.t1003.001"]})
    _write(d, "b.yml", {"id": "b", "logsource": {"product": "windows", "category": "process_access"},
                        "detection": {"selection": {"TargetImage|endswith": "\\foo.exe"}, "condition": "selection"},
                        "tags": ["attack.t1003.001"]})
    # an aggregation rule (not compilable) for a technique with no evaluable rule → a coverage gap
    _write(d, "c.yml", {"id": "c", "logsource": {"product": "windows", "category": "ps"},
                        "detection": {"selection": {"x": "y"}, "condition": "selection | count() by u > 5"},
                        "tags": ["attack.t1059.001"]})

    rep = consume_sigma(d)
    assert rep["total"] == 3
    assert rep["evaluable"] == 2
    assert rep["distinct_detections"] == 1                     # a and b FCA-merged (same field-set)
    assert rep["redundancy"]["collapsed"] == 1
    assert rep["reasons"]["ok"] == 2 and rep["reasons"]["aggregation"] == 1
    assert sum(rep["reasons"].values()) == rep["total"]        # every rule attributed exactly once
    assert rep["techniques_evaluable"] == 1                    # T1003.001 covered
    assert "T1059.001" in rep["techniques_gap"]               # only an aggregation rule → honest gap
    assert rep["ir_roadmap"] == [["aggregation", 1]]
    assert len(rep["cid"]) == 64


@pytest.mark.skipif(not SIGMA.exists(), reason="vendored Sigma corpus not present")
def test_consume_real_corpus_is_internally_consistent():
    rep = consume_sigma()
    assert rep["total"] > 100                                  # a real corpus
    assert sum(rep["reasons"].values()) == rep["total"]        # full attribution, nothing dropped
    assert 0 < rep["evaluable"] <= rep["total"]
    assert rep["distinct_detections"] <= rep["evaluable"]      # dedup never invents detections
    assert rep["techniques_evaluable"] <= rep["techniques_total"]
    assert isinstance(rep["ir_roadmap"], list)                # the roadmap (may be empty if fully consumed)
    assert rep["evaluable_pct"] > 80                          # the condition+keyword parsers consume the bulk
