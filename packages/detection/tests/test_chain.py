"""Chain checker — declarative kill-chain satisfaction (the kerberoast 2-stage spec)."""

from detection.chain import check_chain, kerberoast_chain, stage_authenticate, stage_rc4_fanout


def _tgs(actor, svc, t, enc="0x17"):
    return {"Account_Name": actor, "EventCode": "4769", "Service_Name": svc,
            "Ticket_Encryption_Type": enc, "_time": f"2026-03-04 04:54:{t:02d}.000"}


def _tgt(actor, t=0):
    return {"Account_Name": actor, "EventCode": "4768", "_time": f"2026-03-04 04:53:{t:02d}.000"}


def test_kerberoaster_satisfies_the_chain():
    # an actor that authenticates then fans out RC4 to 8 distinct services in a burst → chain holds
    evs = [_tgt("attacker")] + [_tgs("attacker", f"svc{i}", i) for i in range(8)]
    res = check_chain(evs, kerberoast_chain(n=8), actor_field="Account_Name")
    assert res["satisfied"] == ["attacker"]


def test_enc_downgrade_decoy_is_excluded():
    # RC4 but only ONE service (the enc-downgrade decoy) → S1 fails, chain does not hold
    evs = [_tgt("downgrader")] + [_tgs("downgrader", "svc0", i) for i in range(8)]   # 8 RC4 requests, 1 service
    res = check_chain(evs, kerberoast_chain(n=8), actor_field="Account_Name")
    assert res["satisfied"] == []
    assert ("rc4_fanout", False) in res["per_actor"]["downgrader"]      # localizes: S1 is the failing stage


def test_no_auth_fails_s0():
    # fans out RC4 but never authenticated (no 4768) → S0 fails
    evs = [_tgs("ghost", f"svc{i}", i) for i in range(8)]
    res = check_chain(evs, kerberoast_chain(n=8), actor_field="Account_Name")
    assert res["satisfied"] == []
    assert ("authenticate", False) in res["per_actor"]["ghost"]


def test_aes_fanout_is_not_rc4_kerberoast():
    # high fan-out but AES (0x12), not RC4 → S1 fails (the RC4 characteristic matters)
    evs = [_tgt("aes")] + [_tgs("aes", f"svc{i}", i, enc="0x12") for i in range(8)]
    res = check_chain(evs, kerberoast_chain(n=8), actor_field="Account_Name")
    assert res["satisfied"] == []


def test_stage_predicates_directly():
    roaster = [_tgt("a")] + [_tgs("a", f"s{i}", i) for i in range(8)]
    assert stage_authenticate(roaster)
    assert stage_rc4_fanout(roaster, n=8)
    assert not stage_rc4_fanout(roaster, n=9)        # 8 distinct, threshold 9 → not met
