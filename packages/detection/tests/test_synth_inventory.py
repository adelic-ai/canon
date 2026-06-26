"""Synthetic inventory (L1) — the reusable org model. Tests pin the invariants the multi-log correlation will
depend on: determinism (reproducible test data), unique join keys (IPs/names), and a consistent SPN→account map.
"""

import pytest

from detection.synth.inventory import (
    Host,
    ServiceSpec,
    build_inventory,
)


def test_deterministic_same_seed_identical():
    assert build_inventory(seed=7) == build_inventory(seed=7)        # equality ⇒ reproducible test data


def test_different_seed_differs():
    assert build_inventory(seed=7) != build_inventory(seed=8)


def test_counts_honored():
    inv = build_inventory(seed=1, n_users=25, n_workstations=10)
    assert len(inv.users) == 25
    assert len(inv.workstations()) == 10


def test_usernames_unique():
    inv = build_inventory(seed=3, n_users=40)
    names = [u.username for u in inv.users]
    assert len(names) == len(set(names))


def test_host_names_and_ips_unique():
    inv = build_inventory(seed=2, n_users=40, n_workstations=15)
    names = [h.name for h in inv.hosts]
    ips = [h.ip for h in inv.hosts]
    assert len(names) == len(set(names))
    assert len(ips) == len(set(ips))                                 # IP is a join key — must be unique


def test_every_user_has_an_existing_workstation():
    inv = build_inventory(seed=5)
    ws_names = {h.name for h in inv.workstations()}
    for u in inv.users:
        assert u.workstation in ws_names
        assert inv.user_ip(u.username) is not None                   # the cross-host origin IP resolves


def test_subnets_are_disjoint_by_kind():
    inv = build_inventory(seed=9, ws_subnet="10.1", server_subnet="10.0.0")
    for h in inv.hosts:
        if h.kind == "workstation":
            assert h.ip.startswith("10.1.")
        else:
            assert h.ip.startswith("10.0.0.")


def test_exactly_one_dc():
    inv = build_inventory(seed=4)
    assert sum(1 for h in inv.hosts if h.kind == "dc") == 1


def test_sensitive_hosts_include_dc_and_servers():
    inv = build_inventory(seed=6)
    sens = inv.sensitive_hosts()
    dc = next(h for h in inv.hosts if h.kind == "dc")
    assert dc.name in sens
    assert len(sens) >= 2                                            # DC + at least one crown-jewel server


def test_spn_to_account_map_consistent():
    inv = build_inventory(seed=8)
    m = inv.spn_to_account()
    host_names = {h.name for h in inv.hosts}
    for s in inv.service_accounts:
        assert s.crackable                                           # only crackable user service accounts modeled
        assert s.host in host_names                                  # SPN's host exists
        assert m[s.spn] == s.username                                # map round-trips
    assert len(m) == len(inv.service_accounts)                       # one SPN per account, no collisions


def test_lookup_helpers():
    inv = build_inventory(seed=11)
    h = inv.hosts[0]
    assert inv.host_by_name(h.name) is h
    assert inv.host_by_ip(h.ip) is h
    assert inv.host_by_name("nonexistent.corp.local") is None
    u = inv.users[0]
    assert inv.user_by_name(u.username) is u


def test_requires_a_dc():
    with pytest.raises(ValueError, match="dc"):
        build_inventory(seed=1, servers=(("fileserver", "fs", True),))


def test_rejects_nonpositive_counts():
    with pytest.raises(ValueError):
        build_inventory(seed=1, n_users=0)


def test_service_specs_skipped_when_server_absent():
    # only a DC present → no fileserver/sql/web/exchange → the default service specs resolve to nothing
    inv = build_inventory(seed=1, servers=(("dc", "dc01", True),),
                          services=(ServiceSpec("svc_sql", "MSSQLSvc", "sql", 1433),))
    assert inv.service_accounts == ()
