"""SIEM-side detection — reconstruct the issued-ticket ledger from telemetry and
enforce the state-machine invariant.

This is the *external* detector: it never sees the KDC's in-memory ledger, only
the emitted 4768/4769/4624 events (exactly what a real SIEM has). It rebuilds the
issued set and checks the necessity edge derived from the state machine —

    a presented ticket  ⊢  a prior issuance of it

— classifying each presentation in the shared entailment vocabulary
(``web/detection/three_entailments.html``):

    CONFIRMED  presented hash matches an issuance
    GAP        presented hash has no issuance, and the issuance channel IS collected
               → used-without-issued (a forgery: golden at the TGT layer, silver at
               the service layer). "It was never issued" is ruled in.
    NONE       no issuance channel collected → unobservable, no claim.

Pass-the-ticket is not a GAP — the issuance is present; the *context divergence*
(a ticket issued to one client IP, presented from another) is the signal.

Mirrors ``detection/entailment_gap.py`` and the ticket-integrity Splunk/Sentinel
pages; kept self-contained here so the POC has no canon dependency.
"""

from __future__ import annotations

CONFIRMED = "CONFIRMED"
GAP = "GAP"
NONE = "NONE"
DIVERGENCE = "CONTEXT-DIVERGENCE"


def reconstruct(events: list[dict]) -> dict:
    """Rebuild the issued-ticket registry the KDC does not keep. Returns the issued
    TGT hashes, the issued service-ticket hashes → their issuing 4769, and whether
    each issuance channel is collected at all."""
    issued_tgt = {e["tgt_hash"] for e in events if e["EventID"] == "4768"}
    issued_svc = {e["resp_svc_hash"]: e for e in events if e["EventID"] == "4769"}
    return {
        "issued_tgt": issued_tgt,
        "issued_svc": issued_svc,
        "tgt_channel": any(e["EventID"] == "4768" for e in events),
        "svc_channel": any(e["EventID"] == "4769" for e in events),
    }


def classify(events: list[dict], *, sensitive_hosts=()) -> list[dict]:
    """Walk the telemetry and classify every ticket presentation. Findings carry
    ``outcome`` (CONFIRMED / GAP / NONE / CONTEXT-DIVERGENCE), an ``attack`` label
    when it's an attack, and the presenting event's context."""
    st = reconstruct(events)
    sensitive = set(sensitive_hosts)
    findings: list[dict] = []

    for e in events:
        # golden: a 4769 presents a TGT hash with no issuing 4768
        if e["EventID"] == "4769":
            present = e["req_tgt_hash"] in st["issued_tgt"]
            outcome = CONFIRMED if present else (GAP if st["tgt_channel"] else NONE)
            findings.append({"outcome": outcome, "layer": "TGT", "eid": "4769",
                             "attack": "golden_ticket" if outcome == GAP else None,
                             "client": e["client"], "spn": e["spn"],
                             "presented_hash": e["req_tgt_hash"]})

        # silver / pass-the-ticket: a service logon (4624) against issuance
        elif e["EventID"] == "4624" and (not sensitive or e.get("host") in sensitive):
            issuing = st["issued_svc"].get(e["svc_hash"])
            if issuing is None:
                outcome = GAP if st["svc_channel"] else NONE
                findings.append({"outcome": outcome, "layer": "SERVICE", "eid": "4624",
                                 "attack": "silver_ticket" if outcome == GAP else None,
                                 "account": e["account"], "spn": e["spn"], "host": e.get("host"),
                                 "presented_hash": e["svc_hash"]})
            elif issuing["ip"] != e["ip"]:
                findings.append({"outcome": DIVERGENCE, "layer": "SERVICE", "eid": "4624",
                                 "attack": "pass_the_ticket", "account": e["account"],
                                 "spn": e["spn"], "host": e.get("host"),
                                 "issued_ip": issuing["ip"], "used_ip": e["ip"]})
            else:
                findings.append({"outcome": CONFIRMED, "layer": "SERVICE", "eid": "4624",
                                 "attack": None, "account": e["account"], "spn": e["spn"],
                                 "host": e.get("host")})
    return findings


def counts(findings: list[dict]) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        out[f["outcome"]] = out.get(f["outcome"], 0) + 1
    return out
