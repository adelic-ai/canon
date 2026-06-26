"""Validation (L4) — prove the generated dataset's non-negotiables on the projected logs.

A synthetic test stand is only *valid* if two things hold, and they're easy to get wrong:

1. **Benign is correlated across logs** the same way the attack is — a benign user's activity threads through
   the DC log and their host logons from a *single* source IP. If benign were random-per-log, the attacker
   would be the only correlated thing and any "cross-host detector" would be measuring an artifact.
2. **The attacker is NOT trivially separable by correlation alone** — a naive "same IP in a TGS request *and* a
   sensitive-host logon" signal must over-fire on benign users too, so that the real discriminators (RC4
   downgrade, fan-out, the SPN→account cross-account pivot) are what actually do the work.

These functions measure both on the round-tripped multi-log events, so the generator self-reports its validity
(the instrument-instruments-itself principle — cheaper and more honest than eyeballing dumps).
"""

from __future__ import annotations

from collections import defaultdict


def origin_ips_by_account(events: list[dict], *, ip: str = "IpAddress",
                          user: str = "TargetUserName") -> dict[str, set[str]]:
    """Per account, the set of source IPs it acts from across all logs. A benign user acts from ONE workstation
    IP (coherent); used to confirm benign is correlated, not random-per-log."""
    m: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e.get(user) and e.get(ip):
            m[e[user]].add(e[ip])
    return dict(m)


def naive_correlation_flags(events: list[dict], *, sensitive_hosts, eid: str = "EventID", tgs: str = "4769",
                            logon: str = "4624", ip: str = "IpAddress", host: str = "Computer",
                            logontype: str = "LogonType", network: str = "3") -> set[str]:
    """The NAIVE cross-host signal: source IPs appearing in BOTH a TGS request and a network logon to a
    sensitive host — correlation WITHOUT the discriminators (any encryption, any account, no order). This is
    the thing that must over-fire: benign users also request tickets and log into crown jewels from their IP."""
    roast_ips = {e.get(ip) for e in events if e.get(eid) == tgs and e.get(ip)}
    lateral_ips = {e.get(ip) for e in events
                   if e.get(eid) == logon and e.get(host) in sensitive_hosts
                   and e.get(logontype) == network and e.get(ip)}
    return roast_ips & lateral_ips


def separability_report(events: list[dict], *, sensitive_hosts) -> dict:
    """A compact self-validation readout over a generated dataset's events: how many accounts are
    single-origin (coherent benign), and how many IPs the naive correlation flags (the over-fire that proves
    correlation alone can't isolate the attacker)."""
    origins = origin_ips_by_account(events)
    single_origin = sum(1 for ips in origins.values() if len(ips) == 1)
    naive = naive_correlation_flags(events, sensitive_hosts=sensitive_hosts)
    return {
        "n_accounts": len(origins),
        "single_origin_accounts": single_origin,            # benign coherence: most accounts act from one IP
        "naive_correlation_flagged_ips": len(naive),        # over-fire: ≫ the true campaign count
    }
