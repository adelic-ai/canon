"""kdc — a minimal Kerberos KDC with the state table built in (POC / ground-truth generator).

Rebuilds Kerberos's core exchanges (AS / TGS / AP) with the issued-ticket ledger
KEPT, so the state-machine invariant — *a presented ticket was actually issued* —
is checkable. Forgeries (golden / silver tickets) validate cryptographically (the
stateless KDC can't tell) yet surface as **used-without-issued GAPs** once the
ledger is reconstructed from telemetry. The emitted 4768/4769/4624 events are a
labeled ground-truth feed whose invariants ARE the entailment rules.

Framing: ``web/detection/kerberos_state_table.html``. This package has no canon
dependency — it's a self-contained test-stand and rule-source.
"""

from kdc.attacks import golden_ticket, silver_ticket
from kdc.detect import CONFIRMED, DIVERGENCE, GAP, NONE, classify, counts, reconstruct
from kdc.domain import SERVICE, TGT, Domain, KerberosError
from kdc.model import Principal, Realm

__all__ = [
    "Realm", "Principal", "Domain", "KerberosError", "TGT", "SERVICE",
    "golden_ticket", "silver_ticket",
    "classify", "reconstruct", "counts", "CONFIRMED", "GAP", "NONE", "DIVERGENCE",
]
