"""Benign Kerberos flow — the state machine works and the ledger stays consistent."""

import pytest

from kdc import Domain, KerberosError, Realm, GAP, classify, counts


def _realm() -> Realm:
    return Realm.build(
        users={"alice": "pw-alice"},
        services={"CIFS/dc01": "pw-svc", "HTTP/app": "pw-app"},
        sensitive_hosts={"dc01"},
    )


def test_benign_flow_confirms_and_records():
    d = Domain(_realm())
    tgt = d.as_req("alice", "pw-alice", ip="10.0.0.50")
    st = d.tgs_req(tgt, "CIFS/dc01", ip="10.0.0.50")
    assert d.ap_req(st, "CIFS/dc01", host="dc01", ip="10.0.0.50") is True

    # two issuances recorded; telemetry is exactly 4768 → 4769 → 4624
    assert len(d.ledger) == 2
    assert [e["EventID"] for e in d.events] == ["4768", "4769", "4624"]

    findings = classify(d.events, sensitive_hosts=d.realm.sensitive_hosts)
    assert findings and all(f["outcome"] == "CONFIRMED" for f in findings)
    assert counts(findings).get(GAP, 0) == 0


def test_bad_password_is_rejected_by_preauth():
    d = Domain(_realm())
    with pytest.raises(KerberosError):
        d.as_req("alice", "wrong-password")


def test_unknown_spn_rejected():
    d = Domain(_realm())
    tgt = d.as_req("alice", "pw-alice")
    with pytest.raises(KerberosError):
        d.tgs_req(tgt, "CIFS/does-not-exist")
