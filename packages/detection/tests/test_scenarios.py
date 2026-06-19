"""Synthetic fidelity scenarios — multi-channel/multi-variant labeled instances exercise the cross-channel
rules the single OTRF campaign can't.

Gated on the Sigma corpus: every key T1003.001 variant is caught by ≥1 rule, the catchers span more than one
telemetry channel (defense-in-depth), and feeding the multi-channel corpus to the fidelity scorecard makes more
rules applicable + catching than the single process_access instance.
"""

import pytest

from detection.fidelity_scorecard import technique_fidelity
from detection.scenarios import scenario_positives, t1003_001_scenarios, variant_coverage
from detection.sigma_panel import SIGMA

pytestmark = pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")


def test_every_key_variant_is_caught_across_channels():
    cov = variant_coverage(t1003_001_scenarios())
    # every scenario variant has at least one catching rule (multi-variant coverage)
    uncaught = [(c["variant"], c["channel"]) for c in cov if not c["caught"]]
    assert not uncaught, f"variants with no catching rule: {uncaught}"
    # and detection spans more than one channel — the defense-in-depth point
    channels_with_a_catch = {c["channel"] for c in cov if c["caught"]}
    assert len(channels_with_a_catch) >= 2, channels_with_a_catch


def test_grounding_preserves_detection_end_to_end():
    """Wiring check: ground the scenarios in a benign background, then score fidelity over the injected
    malicious events — the signature survives grounding (contextual fields filled, signature untouched), so
    the catching rules still fire. The realistic background is along for the ride (FP surface)."""
    from synthcyber import grounded_scenario_corpus, t1003_001_scenarios
    background = [{"Computer": "DC", "User": "svc", "Image": "C:\\Windows\\System32\\svchost.exe"}] * 10
    g = grounded_scenario_corpus(t1003_001_scenarios(), background)
    malicious = [e for e, lab in zip(g["events"], g["labels"]) if lab]
    f = technique_fidelity("T1003.001", malicious, corpus_id="grounded", corpus_cid="cid:grounded")
    assert f["rules_catching"] >= 3                         # signature survived grounding → still caught


def test_multichannel_corpus_beats_single_channel_for_fidelity():
    f = technique_fidelity("T1003.001", scenario_positives(t1003_001_scenarios()),
                           corpus_id="synthetic/T1003.001", corpus_cid="cid:synthetic")
    # cross-channel rules now have telemetry to fire on → more catchers + fewer wrong-channel misses than the
    # single process_access OTRF event (which catches ~2 and marks ~53 missing-telemetry)
    assert f["rules_catching"] >= 3
    caught_files = {a["rule"] for a in f["attestations"] if a["coverage"] in ("true", "both")}
    assert any("file_event" in r for r in caught_files)        # a file-channel rule fired
    assert any("comsvcs" in r for r in caught_files)           # the process_access variant still fires
