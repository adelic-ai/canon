"""Two-sided grounded fidelity — recall (catch the injected attacks) AND false positives (fire on the benign
background). A clean synthetic background gives exact FP semantics; a gated real-corpus run shows it on real data
(with the upper-bound caveat)."""

from pathlib import Path

import pytest

from detection.fidelity_scorecard import grounded_fidelity
from detection.sigma_panel import SIGMA
from synthcyber import t1003_001_scenarios

pytestmark = pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")


def test_recall_and_false_positives_on_a_clean_background():
    # a clean benign background: ordinary svchost activity, no LSASS dumping → no rule should FP on it
    background = [{"EventID": "10", "TargetImage": "C:\\Windows\\System32\\svchost.exe",
                  "SourceImage": "C:\\Windows\\System32\\services.exe", "GrantedAccess": "0x1000",
                  "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0x1"} for _ in range(20)]
    f = grounded_fidelity("T1003.001", t1003_001_scenarios(), background)
    assert f["n_malicious"] >= 5 and f["n_benign"] == 20
    assert f["rules_catching"] >= 3                          # recall: the injected attacks are caught
    assert f["clean_catchers"]                               # at least one rule catches AND doesn't FP
    assert any("comsvcs" in r for r in f["clean_catchers"])  # the comsvcs rule is a clean catcher
    assert len(f["cid"]) == 64


@pytest.mark.skipif(not (Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json").exists(),
                    reason="OTRF corpus not present")
def test_grounded_on_a_real_background():
    from synthcyber import load_events
    otrf = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
    background = load_events(str(otrf))[:3000]                # sample for test speed (full run is ~42k events)
    f = grounded_fidelity("T1003.001", t1003_001_scenarios(), background)
    assert f["n_benign"] == 3000 and f["rules_catching"] >= 3  # real Sysmon background; attacks still caught
    # FP counts are an upper bound here (OTRF contains its own unlabeled campaign) — just assert the metric runs
    assert isinstance(f["rules_with_false_positives"], int)
