"""Shadow accumulator — streaming prefix-firing over the kerberoast spec.

Demonstrates the seed's claims: a prefix fires BEFORE completion; state is sparse (a shadow only for an actor
that started a chain); the decay forgets a cold hypothesis (so a too-short τ loses a slow attacker); and the
fire_at_prefix knob spans early-warning (2/3) to complete-chain (3/3).
"""

import math

from detection.chain import _ts, kerberoast_lateral_chain
from detection.shadow import Alert, ShadowAccumulator, _forget

_SENSITIVE = {"DC01.corp.local"}


def _tgt(actor, sec):
    return {"Account_Name": actor, "EventCode": "4768", "_time": f"2026-03-04 05:00:{sec:02d}.000"}


def _tgs(actor, svc, sec, enc="0x17"):
    return {"Account_Name": actor, "EventCode": "4769", "Service_Name": svc,
            "Ticket_Encryption_Type": enc, "_time": f"2026-03-04 05:01:{sec:02d}.000"}


def _logon(actor, host, mins, logontype="3"):
    return {"Account_Name": actor, "EventCode": "4624", "Computer_Name": host,
            "LogonType": logontype, "_time": f"2026-03-04 05:{mins:02d}:00.000"}


def _roast_burst(actor, n=8):
    """A TGT then n distinct RC4 service tickets — the roast prefix (stages 0 and 1)."""
    return [_tgt(actor, 0)] + [_tgs(actor, f"svc{i}/host", i) for i in range(n)]


def _spec(n=8):
    return kerberoast_lateral_chain(sensitive_hosts=_SENSITIVE, n=n)


# ── the prefix fires, and before completion ──────────────────────────────────────────────────────

def test_prefix_fires_before_completion():
    """fire_at_prefix=2 raises at the RC4 burst, before the sensitive logon that completes the chain."""
    acc = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=2)
    stream = _roast_burst("attacker") + [_logon("attacker", "DC01.corp.local", 40)]
    alerts = acc.run(stream)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.actor == "attacker"
    assert a.prefix == 2 and a.completeness < 1.0          # fired on a PREFIX, not the full chain
    pivot = _ts(_logon("attacker", "DC01.corp.local", 40))
    assert a.time < pivot                                   # the warning precedes the crown-jewel pivot


def test_fire_at_full_prefix_requires_completion():
    """fire_at_prefix=3 fires only once the lateral logon lands — the knob spans warning↔completion."""
    acc = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=3)
    roast_only = acc.run(_roast_burst("attacker"))
    assert roast_only == []                                 # roast alone does not complete the chain
    acc2 = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=3)
    full = acc2.run(_roast_burst("attacker") + [_logon("attacker", "DC01.corp.local", 40)])
    assert len(full) == 1 and full[0].prefix == 3 and full[0].completeness == 1.0


# ── sparsity: a shadow only for actors that start a chain ──────────────────────────────────────────

def test_state_is_sparse():
    """Benign actors that only authenticate (everyone does) get a low shadow; non-authenticating none."""
    acc = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=2)
    stream = _roast_burst("attacker")
    stream += [_tgt(f"user{i}", 0) for i in range(50)]      # 50 benign accounts: a TGT, no fan-out
    stream += [_tgs("noise", "svcX/host", 1)]               # a TGS with no TGT and no fan-out
    acc.run(stream)
    # 51 actors reach stage 0 (authenticate); only the attacker advances past it, and none but the attacker
    # is anywhere near firing. Sparsity is real: no shadow carries a meaningful prefix except the attacker's.
    assert acc.shadows["attacker"].prefix == 2
    assert all(s.prefix <= 1 for a, s in acc.shadows.items() if a != "attacker")
    assert "noise" not in acc.shadows                       # a TGS without a TGT never starts a chain


def test_only_attacker_fires():
    acc = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=2)
    stream = _roast_burst("attacker") + [_tgt(f"user{i}", 0) for i in range(20)]
    alerts = acc.run(stream)
    assert [a.actor for a in alerts] == ["attacker"]


# ── decay: a too-short τ forgets the prefix → loses a slow attacker (low-and-slow) ──────────────────

def test_decay_prunes_cold_shadow_losing_slow_attack():
    """With τ short relative to the gap before the pivot, the roast prefix decays and is pruned, so the
    full chain (prefix 3) is never recognized — the low-and-slow caveat, made concrete."""
    # roast at ~05:01, pivot at 06:40 (~99 min ≈ 5940s later). τ=120s ⇒ the prefix is long cold by the pivot.
    acc = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=3, decay_tau_sec=120.0)
    stream = _roast_burst("slow")
    stream.append({"Account_Name": "slow", "EventCode": "4624", "Computer_Name": "DC01.corp.local",
                   "LogonType": "3", "_time": "2026-03-04 06:40:00.000"})
    alerts = acc.run(stream)
    assert alerts == []                                     # the slow pivot is not joined to the cold roast
    assert "slow" not in acc.shadows                        # the shadow was pruned

    # A generous τ keeps the hypothesis warm across the same gap → the chain completes and fires.
    acc2 = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=3, decay_tau_sec=4 * 3600.0)
    assert len(acc2.run(stream)) == 1


# ── the shared forgetting operator ─────────────────────────────────────────────────────────────────

def test_forget_operator():
    assert _forget(0.0, 1.0, 1.0) == 1.0                    # α=1 ⇒ pure observation
    assert _forget(10.0, 0.0, 0.0) == 10.0                  # α=0 ⇒ pure memory
    assert math.isclose(_forget(0.0, 1.0, 0.5), 0.5)        # the EWMA blend


def test_alert_is_serializable_shape():
    acc = ShadowAccumulator(_spec(), actor_field="Account_Name", fire_at_prefix=2)
    [a] = acc.run(_roast_burst("attacker"))
    assert isinstance(a, Alert)
    assert a.n_stages == 3 and 0 < a.completeness <= 1.0 and a.abnormality > 0
