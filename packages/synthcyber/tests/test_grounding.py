"""Real-data grounding — load real logs, profile them, inject correct-by-construction attacks into a real
benign background. Core tests use a tiny in-test corpus; an optional gated test profiles a real ~/data corpus.
"""

import json
from pathlib import Path

import pytest

from synthcyber.grounding import field_profile, ground, load_events, plausible_fill


def test_load_events_json_array_and_jsonl(tmp_path):
    arr = tmp_path / "a.json"
    arr.write_text(json.dumps([{"Image": "a.exe"}, {"Image": "b.exe"}, "notadict"]))
    assert load_events(arr) == [{"Image": "a.exe"}, {"Image": "b.exe"}]   # non-dicts dropped
    jl = tmp_path / "b.jsonl"
    jl.write_text('{"Image": "x.exe"}\n\nnot json\n{"Image": "y.exe"}\n')
    assert load_events(jl) == [{"Image": "x.exe"}, {"Image": "y.exe"}]     # blank/bad lines skipped


def test_field_profile_summarizes_real_distributions():
    events = [{"Image": "svchost.exe", "User": "SYSTEM"},
             {"Image": "svchost.exe", "User": "alice"},
             {"Image": "explorer.exe"}]
    prof = field_profile(events)
    assert prof["Image"]["present_frac"] == 1.0
    assert prof["Image"]["top_values"][0] == "svchost.exe"     # most common real value
    assert prof["User"]["present_frac"] == round(2 / 3, 3)


def test_plausible_fill_uses_real_values_but_keeps_signature():
    profile = {"Computer": {"top_values": ["WIN-DC01"]}, "User": {"top_values": ["alice"]}}
    attack = {"TargetImage": "C:\\Windows\\System32\\lsass.exe"}            # the signature field
    filled = plausible_fill(attack, profile, ["Computer", "User"])
    assert filled["Computer"] == "WIN-DC01" and filled["User"] == "alice"  # filled from real data
    assert filled["TargetImage"] == attack["TargetImage"]                  # signature untouched


def test_ground_injects_attack_into_benign_background_with_correct_labels():
    background = [{"Image": "svchost.exe"}, {"Image": "explorer.exe"}]
    attack = [{"TargetImage": "lsass.exe", "CallTrace": "comsvcs.dll"}]
    g = ground(attack, background)
    assert g["n_background"] == 2 and g["n_attack"] == 1
    assert g["labels"] == [False, False, True]                  # by construction: injected = malicious
    assert g["events"][-1] == attack[0]


_OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"


@pytest.mark.skipif(not _OTRF.exists(), reason="OTRF corpus not present")
def test_grounds_in_a_real_corpus():
    events = load_events(str(_OTRF))
    assert len(events) > 100
    prof = field_profile(events)
    assert prof and any(p["present_frac"] > 0.5 for p in prof.values())    # real fields with real distributions
