"""Realm data model: principals (with long-term keys), tickets, and ticket ops.

A ticket is a plain dict ``{"body": {...}, "seal": "<tag>"}`` — JSON-friendly so
it drops straight into telemetry. ``issue_ticket`` mints one sealed under a
target key; ``unseal`` validates it against a key you hold (returns the body or
None); ``ticket_hash`` (re-exported from :mod:`kdc.crypto`) is the telemetry id.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kdc.crypto import derive_key, seal, ticket_hash, verify

__all__ = ["Principal", "Realm", "issue_ticket", "unseal", "ticket_hash"]


@dataclass(frozen=True)
class Principal:
    name: str
    kind: str          # "user" | "service" | "krbtgt"
    key: bytes


@dataclass
class Realm:
    """The realm's principals and their long-term keys. ``sensitive_hosts`` is the
    crown-jewel set the detector treats as high-value logon targets."""
    krbtgt: Principal
    users: dict[str, Principal] = field(default_factory=dict)
    services: dict[str, Principal] = field(default_factory=dict)   # spn -> service principal
    sensitive_hosts: set[str] = field(default_factory=set)

    @classmethod
    def build(cls, *, users: dict[str, str], services: dict[str, str],
              sensitive_hosts=(), krbtgt_password: str = "krbtgt-master") -> "Realm":
        """``users``/``services`` map name → password; keys are derived from them."""
        r = cls(krbtgt=Principal("krbtgt", "krbtgt", derive_key(krbtgt_password)),
                sensitive_hosts=set(sensitive_hosts))
        for u, pw in users.items():
            r.users[u] = Principal(u, "user", derive_key(pw))
        for spn, pw in services.items():
            r.services[spn] = Principal(spn, "service", derive_key(pw))
        return r


def issue_ticket(kind: str, client: str, target: str, target_key: bytes, clock: int) -> dict:
    """Mint a ticket for ``client`` toward ``target``, sealed under ``target_key``
    (the krbtgt key for a TGT, the service key for a service ticket)."""
    session_key = ticket_hash({"c": client, "t": target, "k": clock})   # deterministic pseudo session key
    body = {"kind": kind, "client": client, "target": target,
            "session_key": session_key, "issued_at": clock}
    return {"body": body, "seal": seal(body, target_key)}


def unseal(ticket: dict, key: bytes) -> dict | None:
    """Return the ticket body iff its seal validates under ``key`` (i.e. the holder
    of ``key`` can decrypt it), else None. This is the *cryptographic* check the
    KDC/service does — it says nothing about whether the ticket was ever issued."""
    body = ticket["body"]
    return body if verify(body, ticket["seal"], key) else None
