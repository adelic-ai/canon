"""Entailment GAP classification — the mechanical test on synthetic ground truth.

The comsvcs MiniDump spawn ENTAILS a VM_READ to lsass. Replaying the SAME anchor
against three hand-authored corpora (known answers) must yield CONFIRMED / GAP /
NONE. This is a *mechanical* correctness test — does the mechanism compute the
intended outcome on controlled input — not an efficacy/data claim.
"""

from detection.entailment_gap import (
    CONFIRMED,
    GAP,
    NONE,
    EntailedMotif,
    Entailment,
    classify,
    classify_entailment,
)

# comsvcs MiniDump spawn (EID 1, join on ProcessGuid)  ⊢  lsass VM_READ (EID 10,
# join on SourceProcessGUID, target lsass). channel = "any EID 10".
SPAWN_ENTAILS_READ = Entailment(
    rationale="a comsvcs MiniDump spawn cannot dump credentials without a VM_READ to lsass",
    anchor=EntailedMotif(
        pred=lambda e: str(e.get("EventID")) == "1" and "comsvcs" in str(e.get("CommandLine", "")),
        join=lambda e: e.get("ProcessGuid"),
    ),
    expected=EntailedMotif(
        pred=lambda e: str(e.get("EventID")) == "10" and "lsass" in str(e.get("TargetImage", "")).lower(),
        join=lambda e: e.get("SourceProcessGUID"),
        channel=lambda e: str(e.get("EventID")) == "10",
    ),
)

_ANCHOR = {"EventID": "1", "ProcessGuid": "G1", "CommandLine": "rundll32 comsvcs.dll MiniDump"}
_READ_G1 = {"EventID": "10", "SourceProcessGUID": "G1", "TargetImage": "C:\\Windows\\System32\\lsass.exe"}
_OTHER_10 = {"EventID": "10", "SourceProcessGUID": "G2", "TargetImage": "C:\\Windows\\notepad.exe"}


def test_full_corpus_is_confirmed():
    # anchor + its entailed read present → CONFIRMED
    res = classify_entailment(SPAWN_ENTAILS_READ, [_ANCHOR, _READ_G1])
    assert res["channel_collected"] is True
    assert res["counts"] == {CONFIRMED: 1, GAP: 0, NONE: 0}
    assert res["findings"][0]["outcome"] == CONFIRMED


def test_read_record_withheld_but_channel_collected_is_gap():
    # the G1 read is absent, but EID 10 IS collected (another EID-10 event exists) →
    # the read happened (entailed), its record is missing → GAP, "didn't happen" ruled out
    res = classify_entailment(SPAWN_ENTAILS_READ, [_ANCHOR, _OTHER_10])
    assert res["channel_collected"] is True
    assert res["counts"] == {CONFIRMED: 0, GAP: 1, NONE: 0}


def test_channel_withheld_entirely_is_none():
    # no EID 10 at all → unobservable → NONE, not a clean bill and not a GAP
    res = classify_entailment(SPAWN_ENTAILS_READ, [_ANCHOR])
    assert res["channel_collected"] is False
    assert res["counts"] == {CONFIRMED: 0, GAP: 0, NONE: 1}


def test_no_anchor_yields_no_findings():
    res = classify_entailment(SPAWN_ENTAILS_READ, [_OTHER_10])
    assert res["findings"] == []
    assert res["counts"] == {CONFIRMED: 0, GAP: 0, NONE: 0}


def test_classify_pure_rule():
    # the three-way rule in isolation
    assert classify(expected_present=True, channel_collected=True) == CONFIRMED
    assert classify(expected_present=True, channel_collected=False) == CONFIRMED
    assert classify(expected_present=False, channel_collected=True) == GAP
    assert classify(expected_present=False, channel_collected=False) == NONE


def test_gap_and_none_are_distinct_on_the_same_missing_read():
    # SAME anchor, read absent both times; the ONLY difference is whether the channel
    # is collected — and that flips GAP → NONE. This is the mechanism's whole point.
    gap = classify_entailment(SPAWN_ENTAILS_READ, [_ANCHOR, _OTHER_10])
    none = classify_entailment(SPAWN_ENTAILS_READ, [_ANCHOR])
    assert gap["counts"][GAP] == 1 and gap["counts"][NONE] == 0
    assert none["counts"][NONE] == 1 and none["counts"][GAP] == 0
