"""Chain checker — declarative kill-chain *satisfaction* over event data (model-checking, not firing).

A kill-chain spec is an ordered list of **stage predicates** over one actor's events; the data *satisfies* the
chain for an actor iff every stage holds. This is the model-checking view of detection — ask "does this
structure exist in the data?" rather than "fire each rule and collect alerts." The stage predicates reuse the
same atoms the detectors compute (the RC4 fan-out stage is the fan-out atom).

First spec: **kerberoast** — `authenticate` (4768) then `RC4-TGS fan-out` (≥ N distinct service tickets, RC4,
in a window). It is the **2-stage prefix** of the full kerberoast→lateral chain: the lateral stage (S2: a
4624 logon to a sensitive host, in order, linked to the cracked SPN) needs multi-stage data that no on-disk
corpus has yet (faker must be extended), so it is deferred. Ordering between stages is also a later rung — this
checks the stages over one actor's event set without enforcing `t(S0) < t(S1)` (auth naturally precedes the
TGS burst, so the prefix is sound without it).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime


def group_by_actor(events: list[dict], actor_field: str) -> dict[str, list[dict]]:
    g: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        a = e.get(actor_field)
        if a is not None:
            g[a].append(e)
    return g


def check_chain(events: list[dict], stages: list[tuple], *, actor_field: str) -> dict:
    """Check which actors satisfy the chain. ``stages`` is ``[(name, predicate)]`` where
    ``predicate(actor_events) -> bool``. An actor satisfies the chain iff EVERY stage holds for its events.
    Returns the satisfying actors + the per-actor per-stage truth (so a near-miss shows which stage failed)."""
    by = group_by_actor(events, actor_field)
    per = {a: [(name, bool(pred(evs))) for name, pred in stages] for a, evs in by.items()}
    satisfied = sorted(a for a, res in per.items() if all(ok for _n, ok in res))
    return {"n_actors": len(by), "satisfied": satisfied, "per_actor": per}


# ── stage predicates for the kerberoast chain ───────────────────────────────────────────────────

def stage_authenticate(evs: list[dict], *, code_field: str = "EventCode", tgt_code: str = "4768") -> bool:
    """S0 — the actor authenticated (a Kerberos TGT request)."""
    return any(e.get(code_field) == tgt_code for e in evs)


def stage_rc4_fanout(evs: list[dict], *, n: int = 8, window_sec: int = 3600,
                     code_field: str = "EventCode", tgs_code: str = "4769",
                     enc_field: str = "Ticket_Encryption_Type", rc4: str = "0x17",
                     svc_field: str = "Service_Name", time_field: str = "_time") -> bool:
    """S1 — RC4 service-ticket fan-out: ≥ ``n`` DISTINCT services requested with RC4 in a ``window_sec`` bin.
    The distinct-service count is the kerberoast signature (note: the request *count* is higher — kerberoasters
    re-request — so this counts distinct, not volume). The same fan-out atom the conformal detector uses, here
    as a boolean stage predicate."""
    rc4_evs = [(datetime.fromisoformat(e[time_field]), e.get(svc_field)) for e in evs
               if e.get(code_field) == tgs_code and e.get(enc_field) == rc4 and e.get(time_field)]
    if not rc4_evs:
        return False
    bins: dict[int, set] = defaultdict(set)
    for t, svc in rc4_evs:
        bins[int(t.timestamp() // window_sec)].add(svc)
    return max(len(s) for s in bins.values()) >= n


def kerberoast_chain(*, n: int = 8, window_sec: int = 3600) -> list[tuple]:
    """The 2-stage kerberoast spec: ``authenticate`` (4768) then ``rc4_fanout`` (≥ n distinct RC4 services /
    window). Pass to :func:`check_chain` with ``actor_field='Account_Name'``."""
    return [
        ("authenticate", lambda evs: stage_authenticate(evs)),
        ("rc4_fanout", lambda evs: stage_rc4_fanout(evs, n=n, window_sec=window_sec)),
    ]
