"""The KDC state machine — with the issued-ticket ledger built in.

A real KDC is **stateless**: it validates a presented ticket *cryptographically*
(the seal decrypts under the krbtgt/service key and holds) and keeps **no**
registry of what it issued — by design, for multi-DC scale. That statelessness
is exactly why a golden ticket works: an attacker holding the krbtgt key forges
a TGT that validates perfectly, and the KDC has no issuance memory to contradict
it (``web/detection/kerberos_state_table.html``).

This POC KDC **keeps the ledger** — every issuance is recorded — so the invariant
that a real KDC cannot enforce becomes checkable:

    a presented ticket  ⊢  a prior issuance of that exact ticket

That necessity edge is the entailment rule, *derived from the state machine*
rather than guessed. The three exchanges are the transitions:

    AS-REQ  → AS-REP   : authenticate, issue a TGT (sealed under krbtgt key)   [emits 4768]
    TGS-REQ → TGS-REP  : present a TGT, issue a service ticket (under svc key)  [emits 4769]
    AP-REQ            : present a service ticket to the service, it validates   [emits 4624]

Each transition appends a telemetry event carrying the ticket hashes — the
ground-truth feed a SIEM-side detector reconstructs the ledger from (see
:mod:`kdc.detect`). A logical clock (not wall-clock) keeps runs deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kdc.model import Realm, issue_ticket, ticket_hash, unseal

TGT = "TGT"
SERVICE = "SERVICE"
RC4 = "0x17"                    # the crackable enc type, carried on 4768/4769 for the roasting corner


class KerberosError(Exception):
    """Raised when a validation the KDC *does* perform fails (bad password, a
    ticket whose seal doesn't decrypt). Forgeries do NOT raise — that's the point."""


@dataclass
class Domain:
    """One realm's KDC + its services, sharing an issued-ticket ledger and a
    telemetry feed. Drive it with :meth:`as_req` → :meth:`tgs_req` → :meth:`ap_req`."""
    realm: Realm
    clock: int = 0
    ledger: dict[str, dict] = field(default_factory=dict)   # ticket_hash -> issuance record
    events: list[dict] = field(default_factory=list)         # the telemetry feed (4768/4769/4624)

    def _tick(self) -> int:
        self.clock += 1
        return self.clock

    def _record(self, ticket: dict, *, issuer_ip: str) -> str:
        h = ticket_hash(ticket)
        self.ledger[h] = {"kind": ticket["body"]["kind"], "client": ticket["body"]["client"],
                          "target": ticket["body"]["target"], "issued_at": ticket["body"]["issued_at"],
                          "issuer_ip": issuer_ip}
        return h

    # ── AS-REQ → AS-REP : issue a TGT ──────────────────────────────────────────
    def as_req(self, client: str, password: str, *, ip: str = "10.0.0.50") -> dict:
        """Authenticate ``client`` (pre-auth: prove knowledge of the long-term key)
        and issue a TGT sealed under the krbtgt key. Records the issuance and emits
        a 4768."""
        p = self.realm.users.get(client)
        from kdc.crypto import derive_key
        if p is None or derive_key(password) != p.key:
            raise KerberosError(f"pre-auth failed for {client!r}")
        t = self._tick()
        tgt = issue_ticket(TGT, client, "krbtgt", self.realm.krbtgt.key, t)
        h = self._record(tgt, issuer_ip=ip)
        self.events.append({"EventID": "4768", "client": client, "tgt_hash": h,
                            "ip": ip, "enc": RC4, "time": t})
        return tgt

    # ── TGS-REQ → TGS-REP : present a TGT, issue a service ticket ───────────────
    def tgs_req(self, tgt: dict, spn: str, *, ip: str = "10.0.0.50") -> dict:
        """Validate the presented ``tgt`` (unseal under the krbtgt key — a forged
        TGT sealed with a stolen krbtgt key validates fine) and issue a service
        ticket for ``spn`` sealed under the service key. Emits a 4769 carrying the
        *presented* TGT hash and the *issued* service-ticket hash."""
        body = unseal(tgt, self.realm.krbtgt.key)
        if body is None or body["kind"] != TGT:
            raise KerberosError("TGT does not validate under the krbtgt key")
        svc = self.realm.services.get(spn)
        if svc is None:
            raise KerberosError(f"unknown SPN {spn!r}")
        t = self._tick()
        st = issue_ticket(SERVICE, body["client"], spn, svc.key, t)
        resp_hash = self._record(st, issuer_ip=ip)
        self.events.append({"EventID": "4769", "client": body["client"], "spn": spn,
                            "req_tgt_hash": ticket_hash(tgt), "resp_svc_hash": resp_hash,
                            "ip": ip, "enc": RC4, "time": t})
        return st

    # ── AP-REQ : present a service ticket to the service ───────────────────────
    def ap_req(self, service_ticket: dict, spn: str, *, host: str, ip: str = "10.0.0.50") -> bool:
        """The service validates the presented ticket by unsealing it under *its
        own* key (a forged silver ticket sealed with the stolen service key
        validates fine — and never touched the KDC). Emits a 4624 network logon."""
        svc = self.realm.services.get(spn)
        if svc is None:
            raise KerberosError(f"unknown SPN {spn!r}")
        body = unseal(service_ticket, svc.key)
        if body is None or body["kind"] != SERVICE:
            raise KerberosError("service ticket does not validate under the service key")
        t = self._tick()
        self.events.append({"EventID": "4624", "account": body["client"], "spn": spn,
                            "svc_hash": ticket_hash(service_ticket), "host": host,
                            "logon_type": "3", "ip": ip, "time": t})
        return True
