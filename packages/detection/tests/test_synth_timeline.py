"""Activity timeline (L2). Tests pin the non-negotiables: determinism, ordering, the causally-labeled
kerberoast→lateral chain with its SPN→account pivot, RC4-fan-out vs AES-benign, and — critically — that benign
is correlated and reaches sensitive hosts, so the attacker is not trivially separable.
"""

import pytest

from detection.synth.inventory import build_inventory
from detection.synth.timeline import AES, RC4, build_timeline

_INV = build_inventory(seed=1)


def _campaigns(acts):
    labels = {a.label for a in acts if a.label}
    return {lab: [a for a in acts if a.label == lab] for lab in labels}


def test_deterministic():
    assert build_timeline(_INV, seed=5) == build_timeline(_INV, seed=5)


def test_ordered_by_time():
    acts = build_timeline(_INV, seed=2)
    assert all(acts[i].time <= acts[i + 1].time for i in range(len(acts) - 1))


def test_has_benign_and_attack():
    acts = build_timeline(_INV, seed=3, n_kerberoasters=3)
    assert any(a.label is None for a in acts)            # benign exists
    assert len(_campaigns(acts)) == 3                    # three causally-labeled campaigns


def test_benign_is_correlated_single_origin():
    """A benign user's whole session originates from their own workstation (one IP after L3) and is ordered —
    benign is correlated, not random-per-log."""
    acts = build_timeline(_INV, seed=4)
    u = _INV.users[0]
    mine = [a for a in acts if a.actor == u.username and a.label is None]
    assert mine, "expected benign activity for the user"
    assert {a.src_host for a in mine} == {u.workstation}   # single origin host → single IP downstream
    auth = [a for a in mine if a.action == "authenticate"]
    first_logon = [a for a in mine if a.action == "logon"]
    assert auth and first_logon and min(a.time for a in auth) <= min(a.time for a in first_logon)


def test_benign_reaches_sensitive_hosts():
    """Benign users legitimately log into crown jewels — so a sensitive-host logon alone is NOT an attack
    signal (the S2-over-fires reality; the attacker can't be isolated by destination)."""
    acts = build_timeline(_INV, seed=6, benign_server_logon_p=1.0)
    sens = _INV.sensitive_hosts()
    benign_sensitive = [a for a in acts if a.label is None and a.action == "logon" and a.dst_host in sens]
    assert benign_sensitive


def test_benign_never_uses_rc4():
    acts = build_timeline(_INV, seed=7)
    benign_tickets = [a for a in acts if a.label is None and a.action == "request_ticket"]
    assert benign_tickets and all(a.attr("enc") == AES for a in benign_tickets)


def test_attack_chain_shape_and_order():
    acts = build_timeline(_INV, seed=8, roast_fanout=10)
    for label, camp in _campaigns(acts).items():
        kinds = [a.action for a in camp]
        assert "authenticate" in kinds
        assert any(a.action == "process_create" and a.target == "Rubeus.exe" for a in camp)
        roast = [a for a in camp if a.action == "request_ticket"]
        assert len({a.target for a in roast}) >= 10        # distinct-SPN fan-out
        assert all(a.attr("enc") == RC4 for a in roast)    # all RC4 (the downgrade)
        lateral = [a for a in camp if a.action == "logon"]
        assert len(lateral) == 1 and lateral[0].attr("logon_type") == "3"
        # time order: authenticate ≤ roast ≤ lateral pivot
        t_auth = min(a.time for a in camp if a.action == "authenticate")
        t_roast = min(a.time for a in roast)
        assert t_auth <= t_roast <= lateral[0].time


def test_pivot_is_cross_account_to_a_service_account():
    """The lateral logon is performed by the CRACKED service account (not the roasting user), from the same
    workstation, against a sensitive host — the SPN→account cross-account pivot."""
    acts = build_timeline(_INV, seed=9)
    spn_acct = set(_INV.spn_to_account().values())
    sens = _INV.sensitive_hosts()
    for label, camp in _campaigns(acts).items():
        roasting_user = label.split("kerberoast:")[1]
        lateral = next(a for a in camp if a.action == "logon")
        assert lateral.actor in spn_acct                   # actor is a service account…
        assert lateral.actor != roasting_user              # …distinct from the roaster (cross-account)
        assert lateral.dst_host in sens                    # …pivoting to a crown jewel
        # the roasting user's workstation is the origin (same IP downstream — cross-host)
        assert lateral.src_host == _INV.user_by_name(roasting_user).workstation


def test_fanout_exceeding_namespace_rejected():
    with pytest.raises(ValueError, match="exceeds"):
        build_timeline(_INV, seed=1, roast_fanout=10_000)
