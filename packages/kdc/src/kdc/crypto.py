"""Surrogate crypto for the KDC POC — deliberately NOT real Kerberos crypto.

A long-term key is ``sha256(password)``; "sealing a ticket under a key" is an
HMAC-SHA256 tag over the ticket body (standing in for "encrypted + MAC'd under
the account's long-term key"). Validating a ticket = recomputing the tag with
the key you hold. This is faithful enough for the two things the POC needs — you
cannot forge a valid seal without the key, and the KDC can validate a ticket
*cryptographically* without any memory of having issued it — which is exactly
why golden/silver forgery works. Real AES/RC4 + PAC signing is out of scope for
v0; the point is the STATE MACHINE and the used-without-issued invariant, not
RFC 4120 fidelity.
"""

from __future__ import annotations

import hashlib
import hmac
import json


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def derive_key(password: str) -> bytes:
    """A principal's long-term key = sha256 of its password (the KDF surrogate)."""
    return hashlib.sha256(password.encode()).digest()


def seal(body: dict, key: bytes) -> str:
    """Seal a ticket body under ``key`` — the HMAC tag stands in for 'encrypted
    under the target account's long-term key'. Only a holder of ``key`` can
    produce (or validate) it."""
    return hmac.new(key, _canon(body), hashlib.sha256).hexdigest()


def verify(body: dict, seal_tag: str, key: bytes) -> bool:
    """True iff ``seal_tag`` is a valid seal of ``body`` under ``key``."""
    return hmac.compare_digest(seal(body, key), seal_tag)


def ticket_hash(ticket: dict) -> str:
    """The 16-hex ticket hash that appears in telemetry — the POC analogue of the
    Windows v2 4768/4769 ticket-hash fields (``ResponseTicket`` /
    ``RequestTicketHash``). Two identical tickets share a hash; a forged ticket
    has its own distinct hash that no issuance event will ever carry."""
    return hashlib.sha256(_canon(ticket)).hexdigest()[:16]
