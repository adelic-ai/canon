"""Round-level off-switch (OCSF slice step 5): native (default/OFF) vs OCSF (ON) in evaluate_round.

Native is the default and unchanged; OCSF mode rewrites the selected rules + normalizes events via an
adapter and fires a coherent pair. Guarded on the SigmaHQ rules (selection needs them); events are synthetic."""

from pathlib import Path

import pytest

from detection.ocsf_adapter import SYSMON_ADAPTER
from detection.round import evaluate_round
from detection.sigma_panel import SIGMA
from detection.vocab import NATIVE, OCSF, VocabularyMismatch

pytestmark = pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")


def test_native_is_the_default_and_explicit_native_matches():
    events = [{"Image": "C:\\Windows\\System32\\rundll32.exe",
               "CommandLine": "rundll32.exe comsvcs.dll, MiniDump 624 dump full"}]
    default = evaluate_round(events, ["T1003.001"], use_rust=False)
    explicit = evaluate_round(events, ["T1003.001"], events_vocab=NATIVE, rules_vocab=NATIVE, use_rust=False)
    assert default["vocab"] == {"events": "native", "rules": "native"}
    assert default["verdicts"] == explicit["verdicts"]      # the switch OFF = unchanged behavior
    assert all("rewrite" not in v for v in default["verdicts"])   # no rewrite warrant in native mode


def test_incoherent_pair_is_refused_at_the_round():
    with pytest.raises(VocabularyMismatch):
        evaluate_round([{"Image": "x"}], ["T1003.001"], events_vocab=OCSF, rules_vocab=NATIVE, use_rust=False)


def test_ocsf_mode_requires_an_adapter():
    with pytest.raises(ValueError, match="adapter"):
        evaluate_round([{"Image": "x"}], ["T1003.001"], events_vocab=OCSF, rules_vocab=OCSF, use_rust=False)


def test_ocsf_round_reports_its_vocab_pair():
    events = [{"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe foo"}]
    res = evaluate_round(events, ["T1003.001"], events_vocab=OCSF, rules_vocab=OCSF,
                         adapter=SYSMON_ADAPTER, use_rust=False)
    assert res["vocab"] == {"events": "ocsf", "rules": "ocsf"}
    # any fired verdict in OCSF mode carries its rewrite warrant (grade + dropped + faithful)
    assert all(set(v["rewrite"]) == {"grade", "dropped", "faithful"} for v in res["verdicts"])
