"""Chain checker — declarative kill-chain *satisfaction* over event data (model-checking, not firing).

A kill-chain spec is an ORDERED list of **stage predicates** over one actor's events; the data *satisfies* the
chain for an actor iff every stage holds **and the stages occur in time order** — each stage at a time at/after
the previous one's. This is the model-checking view of detection — ask "does this structure exist in the
data?" rather than "fire each rule." The stage predicates reuse the same atoms the detectors compute (the RC4
fan-out stage is the fan-out atom).

Stages are **time-yielding**: a stage returns the *earliest time it is satisfied at/after* a lower bound
(``not_before``), or ``None`` if it can't be. :func:`check_chain` threads each satisfied stage's time as the
next stage's lower bound, so ordering falls out of the scan. Pass ``ordered=False`` to degrade to pure
conjunction (existence only, no time order) when events carry no usable timestamp.

First spec: **kerberoast → lateral** — ``authenticate`` (4768) → ``rc4_fanout`` (RC4 TGS fan-out) →
``sensitive_logon`` (a network logon to a crown-jewel host). The conjunction *and* the order both matter:
a network logon to a sensitive host (S2 alone) over-fires; only the kerberoasters fan out RC4 (S1) *and then*
pivot.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime


def _ts(e: dict, time_field: str = "_time") -> float | None:
    v = e.get(time_field)
    if not v:
        return None
    try:
        return datetime.fromisoformat(v).timestamp()
    except ValueError:
        return None


def group_by_actor(events: list[dict], actor_field: str) -> dict[str, list[dict]]:
    g: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        a = e.get(actor_field)
        if a is not None:
            g[a].append(e)
    return g


def check_chain(events: list[dict], stages: list[tuple], *, actor_field: str, ordered: bool = True) -> dict:
    """Check which actors satisfy the chain. ``stages`` is ``[(name, predicate)]`` where
    ``predicate(actor_events, not_before) -> float | None`` returns the earliest satisfaction time at/after
    ``not_before`` (or ``None``). An actor satisfies the chain iff every stage holds and (when ``ordered``)
    each is satisfied at a time ≥ the previous stage's. Returns the satisfying actors + the per-actor per-stage
    truth (a near-miss shows which stage failed)."""
    by = group_by_actor(events, actor_field)
    per: dict[str, list[tuple]] = {}
    satisfied: list[str] = []
    for a, evs in by.items():
        nb: float | None = None
        results: list[tuple] = []
        all_ok = True
        for i, (name, stage) in enumerate(stages):
            t = stage(evs, nb if ordered else None)
            results.append((name, t is not None))
            if t is None:
                all_ok = False
                # fill remaining stages' STANDALONE truth for the diagnostic (which stage(s) failed)
                results.extend((n2, s2(evs, None) is not None) for n2, s2 in stages[i + 1:])
                break
            nb = t
        per[a] = results
        if all_ok:
            satisfied.append(a)
    return {"n_actors": len(by), "satisfied": sorted(satisfied), "per_actor": per}


# ── stage predicates for the kerberoast→lateral chain (time-yielding) ────────────────────────────

def _earliest_at_or_after(times: list[float], not_before: float | None) -> float | None:
    for t in sorted(times):
        if not_before is None or t >= not_before:
            return t
    return None


def stage_authenticate(evs: list[dict], not_before: float | None = None, *,
                       code_field: str = "EventCode", tgt_code: str = "4768",
                       time_field: str = "_time") -> float | None:
    """S0 — earliest Kerberos TGT request (4768) at/after ``not_before``."""
    times = [t for e in evs if e.get(code_field) == tgt_code for t in [_ts(e, time_field)] if t is not None]
    return _earliest_at_or_after(times, not_before)


def stage_rc4_fanout(evs: list[dict], not_before: float | None = None, *, n: int = 8, window_sec: int = 3600,
                     code_field: str = "EventCode", tgs_code: str = "4769",
                     enc_field: str = "Ticket_Encryption_Type", rc4: str = "0x17",
                     svc_field: str = "Service_Name", time_field: str = "_time") -> float | None:
    """S1 — RC4 service-ticket fan-out: the time the threshold (≥ ``n`` DISTINCT RC4 services in a
    ``window_sec`` bin) is reached, at/after ``not_before``. Returns the latest event time of the earliest
    qualifying bin (when the fan-out *completes*), so a later stage must follow it."""
    rc4_evs = [(_ts(e, time_field), e.get(svc_field)) for e in evs
               if e.get(code_field) == tgs_code and e.get(enc_field) == rc4 and _ts(e, time_field) is not None]
    bins: dict[int, list[tuple]] = defaultdict(list)
    for t, svc in rc4_evs:
        bins[int(t // window_sec)].append((t, svc))
    completed = [max(t for t, _s in items) for items in bins.values()
                 if len({s for _t, s in items}) >= n]
    return _earliest_at_or_after(completed, not_before)


def stage_sensitive_logon(evs: list[dict], not_before: float | None = None, *, sensitive_hosts,
                          code_field: str = "EventCode", logon_code: str = "4624",
                          host_field: str = "Computer_Name", logontype_field: str = "LogonType",
                          network_logon: str = "3", time_field: str = "_time") -> float | None:
    """S2 — earliest network logon (LogonType 3) to a sensitive (crown-jewel) host at/after ``not_before``.
    ``sensitive_hosts`` is the deployment's crown-jewel set (parameterized, not baked into the engine)."""
    times = [t for e in evs
             if e.get(code_field) == logon_code and e.get(host_field) in sensitive_hosts
             and e.get(logontype_field) == network_logon
             for t in [_ts(e, time_field)] if t is not None]
    return _earliest_at_or_after(times, not_before)


def kerberoast_chain(*, n: int = 8, window_sec: int = 3600) -> list[tuple]:
    """The 2-stage kerberoast spec: ``authenticate`` (4768) → ``rc4_fanout`` (≥ n distinct RC4 services /
    window). Pass to :func:`check_chain` with ``actor_field='Account_Name'``."""
    return [
        ("authenticate", lambda evs, nb: stage_authenticate(evs, nb)),
        ("rc4_fanout", lambda evs, nb: stage_rc4_fanout(evs, nb, n=n, window_sec=window_sec)),
    ]


def kerberoast_lateral_chain(*, sensitive_hosts, n: int = 8, window_sec: int = 3600) -> list[tuple]:
    """The full 3-stage kerberoast→lateral spec: ``authenticate`` → ``rc4_fanout`` → ``sensitive_logon``,
    *in time order*. The conjunction discriminates (S2 alone over-fires — many accounts log into sensitive
    hosts), and the order enforces "roast THEN pivot" (a sensitive logon before the burst doesn't count)."""
    return kerberoast_chain(n=n, window_sec=window_sec) + [
        ("sensitive_logon", lambda evs, nb: stage_sensitive_logon(evs, nb, sensitive_hosts=sensitive_hosts)),
    ]
