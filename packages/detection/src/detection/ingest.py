"""Attested ingest — the signed-evidence boundary where custody is EARNED, not asserted.

Detection verdicts over plain telemetry report ``custody = NONE`` (an unsigned log carries no integrity —
no faked attestation). Custody is earned only when the bytes arrive with a signed in-toto/DSSE statement
vouching for their content digest. :func:`attest` builds the minimal projection of that statement the
custody fold reads — and the keystone makes it cheap: the vouched ``product_digest`` is just the evidence's
content digest, which (for an evidence source) *is* its CID. One hash, three roles.

A real deployment verifies a DSSE envelope (signature + key trust) here; this is the boundary where that
plugs in. The failure modes are modelled by their inputs: a tampered relay → wrong ``product_digest`` (the
fold returns ``FALSE``); an unsigned claim → ``signed=False`` (``NONE``); a silent feed → ``feed_live=False``
(``NONE`` — the temporal-negation signal, never ``True``).

Pass the returned attestation with the same ``evidence`` bytes to
:func:`detection._verdict.emit_detection_verdict` (``evidence=`` + ``attestation=``).
"""

from __future__ import annotations

from provenance import CustodyAttestation, evidence_digest


def attest(payload: "bytes | str", *, signed: bool = True, feed_live: bool = True) -> CustodyAttestation:
    """The custody attestation a signed ingest carries for ``payload``: an in-toto/DSSE statement
    vouching for the evidence's content digest. ``product_digest`` is set to the bytes' actual digest —
    the honest, intact case. Model a tamper by building a :class:`~provenance.CustodyAttestation` with a
    *different* ``product_digest`` directly; an unsigned/silent feed via ``signed=False`` / ``feed_live=False``."""
    return CustodyAttestation(product_digest=evidence_digest(payload), signed=signed, feed_live=feed_live)
