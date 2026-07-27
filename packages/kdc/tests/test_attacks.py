"""Forgeries validate cryptographically (the KDC can't tell) but reconstruct as GAPs.

The load-bearing assertions: (1) the KDC/service *accept* the forged tickets — no
exception — because they validate under the stolen key; (2) the SIEM-side detector
flags them as used-without-issued GAPs from telemetry alone; (3) the honest
NONE-vs-GAP distinction holds — no issuance channel → NONE (no claim), not a false GAP.
"""

from kdc import (
    CONFIRMED,
    DIVERGENCE,
    Domain,
    GAP,
    Realm,
    classify,
    golden_ticket,
    silver_ticket,
)


def _realm() -> Realm:
    return Realm.build(users={"alice": "pw-alice"},
                       services={"CIFS/dc01": "pw-svc"}, sensitive_hosts={"dc01"})


def test_golden_ticket_validates_but_is_a_gap():
    d = Domain(_realm())
    d.as_req("alice", "pw-alice")                    # a benign login → the 4768 channel is collected
    forged = golden_ticket(d.realm, "attacker")      # forged TGT under the stolen krbtgt key, no AS-REQ
    st = d.tgs_req(forged, "CIFS/dc01")              # KDC ACCEPTS it — validates cryptographically
    assert st["body"]["client"] == "attacker"
    golden = [f for f in classify(d.events) if f["attack"] == "golden_ticket"]
    assert len(golden) == 1
    assert golden[0]["outcome"] == GAP and golden[0]["layer"] == "TGT"


def test_golden_is_none_when_issuance_channel_uncollected():
    d = Domain(_realm())
    d.tgs_req(golden_ticket(d.realm, "attacker"), "CIFS/dc01")   # no 4768 anywhere
    f = [x for x in classify(d.events) if x["layer"] == "TGT"]
    assert f and f[0]["outcome"] == "NONE"           # unobservable → no claim, not a false GAP


def test_silver_ticket_validates_but_is_a_gap_at_the_service():
    d = Domain(_realm())
    tgt = d.as_req("alice", "pw-alice")
    d.tgs_req(tgt, "CIFS/dc01")                       # a benign 4769 → the service-issuance channel is collected
    forged = silver_ticket(d.realm, "CIFS/dc01", "attacker")
    assert d.ap_req(forged, "CIFS/dc01", host="dc01") is True     # service ACCEPTS it; never hit the KDC
    silver = [f for f in classify(d.events, sensitive_hosts=d.realm.sensitive_hosts)
              if f["attack"] == "silver_ticket"]
    assert len(silver) == 1
    assert silver[0]["outcome"] == GAP and silver[0]["layer"] == "SERVICE"


def test_silver_is_none_when_service_channel_uncollected():
    d = Domain(_realm())
    d.ap_req(silver_ticket(d.realm, "CIFS/dc01", "attacker"), "CIFS/dc01", host="dc01")  # only a 4624
    f = [x for x in classify(d.events, sensitive_hosts=d.realm.sensitive_hosts) if x["layer"] == "SERVICE"]
    assert f and f[0]["outcome"] == "NONE"


def test_pass_the_ticket_is_context_divergence_not_a_gap():
    d = Domain(_realm())
    tgt = d.as_req("alice", "pw-alice", ip="10.0.0.50")
    st = d.tgs_req(tgt, "CIFS/dc01", ip="10.0.0.50")             # issued to .50
    d.ap_req(st, "CIFS/dc01", host="dc01", ip="10.9.9.9")        # a real ticket, used from a different IP
    ptt = [f for f in classify(d.events, sensitive_hosts=d.realm.sensitive_hosts)
           if f["attack"] == "pass_the_ticket"]
    assert len(ptt) == 1 and ptt[0]["outcome"] == DIVERGENCE


def test_a_clean_run_has_no_findings_above_confirmed():
    d = Domain(_realm())
    tgt = d.as_req("alice", "pw-alice", ip="10.0.0.50")
    st = d.tgs_req(tgt, "CIFS/dc01", ip="10.0.0.50")
    d.ap_req(st, "CIFS/dc01", host="dc01", ip="10.0.0.50")
    outcomes = {f["outcome"] for f in classify(d.events, sensitive_hosts=d.realm.sensitive_hosts)}
    assert outcomes == {CONFIRMED}
