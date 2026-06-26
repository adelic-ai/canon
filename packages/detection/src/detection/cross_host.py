"""Cross-host correlation — the join the per-actor chain checker cannot express (the dangling rung, now real).

:mod:`detection.chain` groups by ONE account, so it structurally cannot see the kerberoast pivot: account A
roasts an SPN, and the **cracked service account** — a *different* account — logs into a crown jewel. This joins
**across hosts and accounts**:

    RC4 TGS fan-out from a source IP  ⋈  network logon to a sensitive host, from the SAME IP, BY the service
    account behind one of the roasted SPNs, AFTER the roast.

The keys are the **IP** (cross-host: the DC's 4769 and the crown jewel's 4624 carry the same client IP) + the
**SPN→account map** (cross-account: the roasted SPN's account is the logon's account) + **time order**. This is
the relational join the attack-graph view always wanted; it runs over the *union* of the multi-log events (each
event's ``Computer`` says which log it came from), not one actor's stream.

Field names are parameterized (defaults are the EVTX/Sigma names :mod:`detection.evtx_xml` emits), so it runs on
real-schema events. ``spn_to_account`` and ``sensitive_hosts`` are deployment inputs (from the asset inventory).
"""

from __future__ import annotations

from collections import defaultdict

from detection.chain import _ts


def _fanout_burst(roasts: list[tuple], n: int, window_sec: int) -> tuple[float, str, frozenset] | None:
    """Over one IP's RC4 TGS requests ``[(t, spn, account)]``, the earliest ``window_sec`` bin holding ≥ ``n``
    distinct SPNs. Returns ``(completion_time, requesting_account, distinct_spns)`` or ``None``."""
    bins: dict[int, list[tuple]] = defaultdict(list)
    for t, spn, acct in roasts:
        bins[int(t // window_sec)].append((t, spn, acct))
    best: tuple[float, str, frozenset] | None = None
    for items in bins.values():
        spns = frozenset(s for _t, s, _a in items)
        if len(spns) >= n:
            complete = max(t for t, _s, _a in items)
            acct = items[0][2]
            if best is None or complete < best[0]:
                best = (complete, acct, spns)
    return best


def kerberoast_lateral_join(events: list[dict], *, spn_to_account: dict[str, str], sensitive_hosts, n: int = 8,
                            window_sec: int = 3600, eid: str = "EventID", tgs: str = "4769", logon: str = "4624",
                            enc: str = "TicketEncryptionType", rc4: str = "0x17", svc: str = "ServiceName",
                            ip: str = "IpAddress", host: str = "Computer", user: str = "TargetUserName",
                            logontype: str = "LogonType", network: str = "3",
                            time_field: str = "TimeCreated") -> list[dict]:
    """Detect cross-host kerberoast→lateral chains over the union of multi-log events. Returns one dict per
    detection: ``{src_ip, roaster, cracked_account, target_host, roast_time, logon_time, roasted_spns}``."""
    roasts_by_ip: dict[str, list[tuple]] = defaultdict(list)
    logons_by_ip: dict[str, list[tuple]] = defaultdict(list)
    for e in events:
        if e.get(eid) == tgs and e.get(enc) == rc4 and e.get(ip):
            t = _ts(e, time_field)
            if t is not None:
                roasts_by_ip[e[ip]].append((t, e.get(svc), e.get(user)))
        elif e.get(eid) == logon and e.get(host) in sensitive_hosts and e.get(logontype) == network and e.get(ip):
            t = _ts(e, time_field)
            if t is not None:
                logons_by_ip[e[ip]].append((t, e.get(user), e.get(host)))

    out: list[dict] = []
    for src_ip, roasts in roasts_by_ip.items():
        burst = _fanout_burst(roasts, n, window_sec)
        if burst is None:
            continue
        roast_time, roaster, roasted = burst
        cracked = {spn_to_account[s] for s in roasted if s in spn_to_account}   # cross-account pivot
        if not cracked:
            continue
        for t, acct, h in sorted(logons_by_ip.get(src_ip, [])):
            if t >= roast_time and acct in cracked and acct != roaster:         # same IP, cracked acct, after
                out.append({"src_ip": src_ip, "roaster": roaster, "cracked_account": acct, "target_host": h,
                            "roast_time": roast_time, "logon_time": t, "roasted_spns": sorted(roasted)})
                break
    return out
