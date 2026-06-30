"""Tiered Golden/Pass-the-Ticket detector over the synth 4768/4769 stream. Pins the tier story:
the 2024-patch ticket hashes give an exact hash anti-join that catches everything cleanly; without them
the detector degrades honestly — it keeps only the fabricated-account Golden heuristic and LOSES PtT and
active-account Golden entirely (NONE, never a faked pass). And no false positives on benign + kerberoast.
"""

from detection.kerberos_tickets import detect_ticket_attacks, detect_ticket_attacks_synth
from detection.synth.emit import labeled_events
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline


def test_hash_tier_catches_golden_and_ptt_no_fp():
    r = detect_ticket_attacks_synth(seed=1, patched=True)
    # all three injected attacks (PtT + golden-on-active-user + golden-ghost) caught, every one at hash tier
    assert r["n_labeled_attacks"] == 3
    assert len(r["verdicts"]) == 3
    assert r["tiers"] == ["hash"]
    assert "golden" in r["kinds"] and "pass-the-ticket" in r["kinds"]
    # verdicts land on the attack principals, not benign users (no false positive)
    flagged = {v["account"] for v in r["verdicts"]}
    assert "svc_fakeadmin" in flagged


def test_unpatched_degrades_to_metadata_and_loses_ptt():
    r = detect_ticket_attacks_synth(seed=1, patched=False)
    # without ticket hashes only the fabricated-account golden survives — at LOW (metadata) warrant
    assert [v["kind"] for v in r["verdicts"]] == ["possible-golden"]
    assert r["tiers"] == ["metadata"]
    # PtT and the active-user golden are undetectable without the hash -> honestly absent (NONE, not faked)
    assert "pass-the-ticket" not in r["kinds"]
    assert all(v["account"] != "charles.lopez" for v in r["verdicts"])


def test_no_false_positives_on_benign_and_kerberoast():
    inv = build_inventory(seed=1)
    acts = build_timeline(inv, seed=1, include_ticket_attacks=False)   # benign + kerberoast only
    events = [e for e, _ in labeled_events(acts, inv, ticket_hashes=True)]
    verdicts = detect_ticket_attacks(events)
    # benign sessions + roasts all present a matched TGT hash from the issuing host -> nothing flagged
    assert verdicts == []
