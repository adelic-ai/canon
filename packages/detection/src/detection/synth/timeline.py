"""Activity timeline — the single source of truth (L2 of the activity-first generator).

One ordered stream of abstract **activities** over the L1 inventory: per-entity **benign** behavior over N days
PLUS the causally-labeled **kerberoast→lateral** campaign. This is the *world*, before any log exists; L3
projects each activity into the WinEventLog XML of every log it touches, with the inventory's IPs / SPN→account
map / sensitive-host set as the cross-host join keys.

Two non-negotiables, baked in here rather than bolted on:
- **Benign is correlated too.** A benign user's TGT → service tickets → logons all originate from the *same*
  workstation (one IP, time-ordered), and benign users legitimately log into sensitive hosts. So the attacker
  is *not* trivially separable by "being the only correlated thing" — the real discriminators (RC4 downgrade,
  fan-out, the SPN→account pivot, abnormality) have to do the work, exactly as in reality.
- **Attack labels are causal**, not judgments: an activity is labeled because the generator *ran* that campaign,
  so the labels are ground truth for both detection (recall) and the cross-log correlation task.

An :class:`Activity` is vocabulary-neutral (host *names*, not IPs; abstract actions). It carries enough for L3
to render it: actor, action, source/target host, target (SPN/image), and typed attrs (encryption, logon type,
process image/guid). Frozen + hashable, so a timeline is comparable — ``build_timeline(...seed=k)`` reproduces.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from detection.synth.inventory import Inventory

# A fixed epoch base so timelines are reproducible (no wall-clock). 2024-01-01 00:00:00 UTC.
_START = 1_704_067_200
_DAY = 86_400

RC4 = "0x17"      # the crackable/loud encryption (kerberoast downgrade signal)
AES = "0x12"      # AES256 — the benign default


@dataclass(frozen=True)
class Activity:
    """One abstract action, before projection to any log. ``src_host``/``dst_host`` are host *names* (L3 resolves
    IPs from the inventory — the inventory stays the single source of IP truth). ``label`` is None for benign or a
    campaign id (``kerberoast:<user>``) for a causally-injected attack step."""
    time: float
    actor: str
    action: str                                   # authenticate | request_ticket | logon | process_create
    src_host: str | None = None
    dst_host: str | None = None
    target: str | None = None                     # SPN (request_ticket) | image (process_create)
    attrs: tuple[tuple[str, str], ...] = ()       # sorted (k,v): enc, logon_type, image, guid…
    label: str | None = None

    def attr(self, key: str) -> str | None:
        return next((v for k, v in self.attrs if k == key), None)


def _attrs(**kw: str) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((k, str(v)) for k, v in kw.items() if v is not None))


def build_timeline(inv: Inventory, *, seed: int, days: int = 5, n_kerberoasters: int = 3,
                   roast_fanout: int = 10, benign_server_logon_p: float = 0.4) -> list[Activity]:
    """Generate the ordered activity timeline over ``inv``. Deterministic in ``seed``. ``roast_fanout`` distinct
    SPNs are requested per roast (must be ≤ ``len(inv.all_spns())``); the cracked account is one of the crackable
    SPNs in that set (the pivot). Returns activities sorted by ``(time, actor, action)``."""
    spns = inv.all_spns()
    crackable = list(inv.spn_to_account())
    if roast_fanout > len(spns):
        raise ValueError(f"roast_fanout {roast_fanout} exceeds the domain's {len(spns)} SPNs")
    if not crackable:
        raise ValueError("inventory has no crackable service accounts — cannot model the kerberoast pivot")

    rng = random.Random(seed)
    acts: list[Activity] = []
    kerberoasters = set(rng.sample([u.username for u in inv.users], min(n_kerberoasters, len(inv.users))))
    sensitive = sorted(inv.sensitive_hosts())

    # ── benign: every user, a daily work session, all from their own workstation (correlated by construction) ──
    for u in inv.users:
        ws = u.workstation
        for d in range(days):
            s0 = _START + d * _DAY + rng.randint(7 * 3600, 10 * 3600)        # a morning login
            acts.append(Activity(s0, u.username, "authenticate", ws, _dc(inv), attrs=_attrs(enc=AES)))
            acts.append(Activity(s0 + 5, u.username, "logon", ws, ws, attrs=_attrs(logon_type="2")))  # own WS
            for _ in range(rng.randint(1, 3)):                               # a few benign service tickets (AES)
                acts.append(Activity(s0 + rng.randint(10, 7200), u.username, "request_ticket", ws, _dc(inv),
                                     target=rng.choice(spns), attrs=_attrs(enc=AES)))
            if rng.random() < benign_server_logon_p:                         # benign reaches servers — incl. sensitive
                acts.append(Activity(s0 + rng.randint(60, 7200), u.username, "logon", ws,
                                     rng.choice(sensitive), attrs=_attrs(logon_type="3")))

    # ── benign service accounts: occasional service logons to their own host ──
    for sa in inv.service_accounts:
        for d in range(days):
            if rng.random() < 0.5:
                t = _START + d * _DAY + rng.randint(0, _DAY)
                acts.append(Activity(t, sa.username, "logon", sa.host, sa.host, attrs=_attrs(logon_type="5")))

    # ── attack: each kerberoaster runs authenticate → Rubeus → RC4 fan-out → lateral logon (causally labeled) ──
    for user in sorted(kerberoasters):
        label = f"kerberoast:{user}"
        ws = inv.user_by_name(user).workstation
        d = rng.randrange(days)
        t0 = _START + d * _DAY + rng.randint(11 * 3600, 15 * 3600)           # mid-day
        acts.append(Activity(t0, user, "authenticate", ws, _dc(inv), attrs=_attrs(enc=RC4), label=label))
        acts.append(Activity(t0 + 30, user, "process_create", ws, ws, target="Rubeus.exe",
                             attrs=_attrs(image="C:\\Tools\\Rubeus.exe", guid=f"{{guid-{user}}}"), label=label))
        # RC4 fan-out — roast_fanout DISTINCT SPNs, one guaranteed crackable (the pivot target)
        cracked_spn = rng.choice(crackable)
        others = rng.sample([s for s in spns if s != cracked_spn], roast_fanout - 1)
        for i, spn in enumerate([cracked_spn] + others):
            acts.append(Activity(t0 + 60 + i * 3, user, "request_ticket", ws, _dc(inv), target=spn,
                                 attrs=_attrs(enc=RC4), label=label))
        # offline crack (no event) → lateral logon AS the cracked service account, same WS IP, to a crown jewel
        svc = inv.spn_to_account()[cracked_spn]
        acts.append(Activity(t0 + rng.randint(30 * 60, 180 * 60), svc, "logon", ws, rng.choice(sensitive),
                             attrs=_attrs(logon_type="3"), label=label))

    acts.sort(key=lambda a: (a.time, a.actor, a.action))
    return acts


def _dc(inv: Inventory) -> str:
    return next(h.name for h in inv.hosts if h.kind == "dc")
