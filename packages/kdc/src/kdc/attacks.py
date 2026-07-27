"""Ticket forgeries — crypto-valid, state-inconsistent.

Each forge here produces a ticket that **validates cryptographically** (the KDC
or service will unseal it and accept it) but was **never issued** — no ledger
record, no issuance telemetry. That gap between "validates" and "was issued" is
the whole thesis: the KDC's statelessness can't see it; a reconstructed ledger
(:mod:`kdc.detect`) can.

The attacker is assumed to hold the relevant long-term key (the compromise that
precedes the forgery): the krbtgt key for a golden ticket, a service account key
for a silver ticket. Pass-the-ticket needs no key — it reuses a legitimately
issued ticket from a different client context.
"""

from __future__ import annotations

from kdc.domain import SERVICE, TGT
from kdc.model import Realm, issue_ticket

# a fabricated clock the attacker stamps on forged tickets — distinct from any real
# issuance, so the forged ticket's hash appears in no 4768/4769 issuance event.
FORGED_AT = 999_999


def golden_ticket(realm: Realm, client: str, *, clock: int = FORGED_AT) -> dict:
    """Forge a TGT for ``client`` sealed under the stolen krbtgt key, WITHOUT an
    AS-REQ. It validates under the krbtgt key (so ``tgs_req`` accepts it), but no
    4768 ever recorded its hash → the reconstructed ledger flags it as a GAP.
    Golden ticket ⇒ krbtgt compromise ⇒ domain persistence."""
    return issue_ticket(TGT, client, "krbtgt", realm.krbtgt.key, clock)


def silver_ticket(realm: Realm, spn: str, client: str, *, clock: int = FORGED_AT) -> dict:
    """Forge a SERVICE ticket for ``spn`` sealed under the stolen service-account
    key. Presented straight to the service (``ap_req``) it validates — and it never
    contacts the KDC, so no 4769 exists for it. Detectable only by fusing the
    service-host logon (4624) against issuance: the member-side frontier."""
    svc = realm.services[spn]
    return issue_ticket(SERVICE, client, spn, svc.key, clock)
