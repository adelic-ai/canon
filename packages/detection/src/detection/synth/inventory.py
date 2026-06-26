"""Synthetic enterprise inventory — the reusable org model (L1 of the activity-first generator).

The deterministic substrate every scenario draws on: **users** (with a department/peer-group + a home
workstation), **hosts** (workstations + servers, each a unique IP), and user **service accounts** (each with a
crackable SPN). Generalizes the hardcoded org in the faker-kerberos prototype into a seeded, parameterized,
reproducible model — *same seed → identical inventory* (stable test data is the point).

**Dependency-free and seeded** via a local RNG (no global state, no faker): the realism that matters for this
generator lives in *structure* — consistent IPs, the SPN→account map, host kinds, the sensitive-host set —
because those are the cross-host **join keys** the multi-log correlation hangs on, not name variety.

Downstream (L2+): the activity timeline draws actors/hosts from here; the projection layer uses host IPs, the
SPN→account map, and the sensitive-host set as the keys that stitch one activity across multiple logs.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# Embedded name corpus — enough variety for a realistic org without a faker dependency. Combined first.last
# gives ~hundreds of distinct usernames; a numeric suffix breaks any residual collision deterministically.
_FIRST = ("james", "mary", "robert", "patricia", "john", "jennifer", "michael", "linda", "david", "elizabeth",
          "william", "barbara", "richard", "susan", "joseph", "jessica", "thomas", "sarah", "charles", "karen",
          "maria", "debra", "jill", "diana", "jeremy", "christopher", "nancy", "daniel", "lisa", "matthew")
_LAST = ("smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez",
         "hernandez", "lopez", "gonzalez", "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
         "montgomery", "gardner", "rhodes", "foster", "hall", "rivera", "campbell", "mitchell", "carter", "roberts")
_DEPARTMENTS = ("finance", "engineering", "it", "sales", "operations", "hr")


@dataclass(frozen=True)
class Host:
    """A machine on the network. ``ip`` and ``name`` are unique across the inventory; ``kind`` drives behavior
    and ``sensitive`` marks a crown-jewel host (a lateral-movement target)."""
    name: str                       # FQDN, e.g. "WS001.corp.local"
    ip: str
    kind: str                       # "workstation" | "dc" | "fileserver" | "sql" | "web" | "exchange" | …
    sensitive: bool = False


@dataclass(frozen=True)
class User:
    """A human account. ``workstation`` is the Host.name of their primary machine — the source of their
    logons, and the IP that ties their activity together across logs."""
    username: str                   # "first.last"
    display_name: str               # "First Last"
    department: str                 # peer-group, for later baseline/peer comparison
    workstation: str                # Host.name


@dataclass(frozen=True)
class ServiceAccount:
    """A *user* service account behind an SPN — the kerberoast target. ``crackable`` is True for these (weak,
    human-set passwords); machine accounts (uncrackable 120-char passwords) are intentionally not modeled."""
    username: str                   # "svc_sql"
    spn: str                        # "MSSQLSvc/sqlserver.corp.local:1433"
    host: str                       # Host.name the service runs on
    crackable: bool = True


@dataclass(frozen=True)
class ServiceSpec:
    """A recipe for a service account, resolved against the inventory's servers at build time."""
    account: str                    # "svc_sql"
    spn_class: str                  # "MSSQLSvc"
    host_kind: str                  # "sql" — resolved to that server's FQDN
    port: int | None = None


# Default servers: (kind, hostlabel, sensitive). DC + fileserver + SQL are crown jewels.
_DEFAULT_SERVERS = (
    ("dc", "dc01", True),
    ("fileserver", "fileserver", True),
    ("sql", "sqlserver", True),
    ("web", "webserver", False),
    ("exchange", "exchange", False),
)

# Default user service accounts, each tied to a server kind (skipped if that server isn't present).
_DEFAULT_SERVICES = (
    ServiceSpec("svc_sql", "MSSQLSvc", "sql", 1433),
    ServiceSpec("svc_fileshare", "CIFS", "fileserver"),
    ServiceSpec("svc_web", "HTTP", "web"),
    ServiceSpec("svc_backup", "HOST", "fileserver"),
    ServiceSpec("svc_exchange", "exchangeMDB", "exchange"),
)


@dataclass(frozen=True)
class Inventory:
    """A complete synthetic org. Frozen + tuple-valued, so ``build_inventory(seed=k) == build_inventory(seed=k)``
    is true — determinism is checkable by equality. Derived views (maps, filters) are computed on demand so they
    never become part of identity."""
    domain: str
    hosts: tuple[Host, ...]
    users: tuple[User, ...]
    service_accounts: tuple[ServiceAccount, ...]

    def host_by_name(self, name: str) -> Host | None:
        return next((h for h in self.hosts if h.name == name), None)

    def host_by_ip(self, ip: str) -> Host | None:
        return next((h for h in self.hosts if h.ip == ip), None)

    def user_by_name(self, username: str) -> User | None:
        return next((u for u in self.users if u.username == username), None)

    def workstations(self) -> tuple[Host, ...]:
        return tuple(h for h in self.hosts if h.kind == "workstation")

    def servers(self) -> tuple[Host, ...]:
        return tuple(h for h in self.hosts if h.kind != "workstation")

    def sensitive_hosts(self) -> frozenset[str]:
        """Crown-jewel host *names* — the lateral-movement targets (the chain checker's ``sensitive_hosts``)."""
        return frozenset(h.name for h in self.hosts if h.sensitive)

    def spn_to_account(self) -> dict[str, str]:
        """The kerberoast pivot map: SPN → service-account username. Roasting an SPN yields *this* account,
        whose subsequent logon is the cross-account leg of the chain."""
        return {s.spn: s.username for s in self.service_accounts}

    def user_ip(self, username: str) -> str | None:
        """The IP a user's activity originates from (their workstation) — the cross-host join key."""
        u = self.user_by_name(username)
        if u is None:
            return None
        ws = self.host_by_name(u.workstation)
        return ws.ip if ws else None


def _username(rng: random.Random, seen: set[str]) -> str:
    """A unique ``first.last`` username; a numeric suffix breaks collisions deterministically."""
    for _ in range(10_000):
        cand = f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}"
        if cand not in seen:
            seen.add(cand)
            return cand
    # exhausted the corpus — append a counter (deterministic given the RNG stream)
    base = f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}"
    i = 1
    while f"{base}{i}" in seen:
        i += 1
    seen.add(f"{base}{i}")
    return f"{base}{i}"


def build_inventory(*, seed: int, n_users: int = 40, n_workstations: int = 15, domain: str = "corp.local",
                    servers: tuple = _DEFAULT_SERVERS, services: tuple = _DEFAULT_SERVICES,
                    ws_subnet: str = "10.1", server_subnet: str = "10.0.0") -> Inventory:
    """Build a deterministic synthetic org. ``seed`` fully determines the result. Servers land in
    ``server_subnet`` (e.g. ``10.0.0.x``), workstations in ``ws_subnet`` (e.g. ``10.1.a.b``) — disjoint ranges,
    every IP and host name unique. Each user gets a department and a home workstation; each service spec whose
    server kind is present yields a crackable SPN account.

    Raises ``ValueError`` if no DC is among ``servers`` (every AD org has one) or if counts are non-positive."""
    if n_users <= 0 or n_workstations <= 0:
        raise ValueError("n_users and n_workstations must be positive")
    if not any(kind == "dc" for kind, _label, _sens in servers):
        raise ValueError("servers must include exactly one 'dc' (an AD org needs a domain controller)")

    rng = random.Random(seed)
    hosts: list[Host] = []
    server_by_kind: dict[str, Host] = {}

    # servers — server subnet, sequential
    for n, (kind, label, sensitive) in enumerate(servers, start=1):
        h = Host(f"{label}.{domain}", f"{server_subnet}.{n}", kind, sensitive)
        hosts.append(h)
        server_by_kind[kind] = h

    # workstations — ws subnet, sequential (a.b so it scales past /24)
    for i in range(1, n_workstations + 1):
        oct3, oct4 = (i - 1) // 254, (i - 1) % 254 + 1
        hosts.append(Host(f"WS{i:03d}.{domain}", f"{ws_subnet}.{oct3}.{oct4}", "workstation", False))

    workstations = [h for h in hosts if h.kind == "workstation"]

    # users — unique first.last, a department, a home workstation
    seen: set[str] = set()
    users = tuple(
        User(u, " ".join(p.capitalize() for p in u.split(".")), rng.choice(_DEPARTMENTS),
             rng.choice(workstations).name)
        for u in (_username(rng, seen) for _ in range(n_users))
    )

    # service accounts — one per spec whose server kind exists
    svc = tuple(
        ServiceAccount(spec.account,
                       f"{spec.spn_class}/{server_by_kind[spec.host_kind].name}"
                       + (f":{spec.port}" if spec.port else ""),
                       server_by_kind[spec.host_kind].name, True)
        for spec in services if spec.host_kind in server_by_kind
    )

    return Inventory(domain, tuple(hosts), users, svc)
