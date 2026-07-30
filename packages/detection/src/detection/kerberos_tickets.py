"""Tiered Kerberos ticket-forgery / reuse detector — Golden ticket and Pass-the-Ticket from 4768/4769.

The 2024 Windows patch added a **Ticket Information** section to Security events 4768 (TGT request) and
4769 (TGS request): a **Request ticket hash** (the TGT being presented) and a **Response ticket hash**
(the ticket being issued). On a *patched* DC this gives an exact cross-event, cross-DC join key — which is
what the prior count-heuristic approaches (e.g. Splunk's ``sum/max != 2`` over 4768/4769 per user) only
approximated. So the detector is **tiered by the warrant the telemetry actually supports**:

* **hash tier (high):** match the 4769 ``Request ticket hash`` against the set of issued ``Response ticket
  hash`` values from every DC's 4768. No match anywhere → forged TGT = **Golden**. Match, but the issuing
  4768's source IP ≠ this 4769's source IP → the TGT is being used from another host = **Pass-the-Ticket**.
* **metadata tier (low):** an *un*patched DC emits no hashes. Fall back to the account-level anti-join
  (a 4769 for an account with no 4768 issuance seen at all → *possible* Golden) at LOW warrant — this is
  FP-prone (S4U/constrained delegation, cross-DC gaps, collection start) and **cannot** see PtT at all
  (no per-ticket identity to tie a use to a host).
* **NONE:** neither hashes nor a conclusive metadata signal → honest unknown (e.g. PtT on an unpatched DC).

So losing the hash fields is not a binary on/off: Golden degrades to a noisy heuristic and **PtT becomes
undetectable** — the detector says which, rather than silently pretending coverage. Cross-DC is handled by
construction: pass events from all DCs; the hash (or account) is the join key, not the DC.

Field names below are **CONFIRMED** against a real patched Windows Server 2025 DC capture (2026-07-30). They
are ASYMMETRIC across the two events: 4768 (issuance) carries the issued-TGT hash as ``ResponseTicket`` (no
"Hash" suffix); 4769 (service-ticket request) carries the presented-TGT hash as ``RequestTicketHash`` and the
issued service-ticket hash as ``ResponseTicketHash``. The golden/PtT join is therefore 4769
``RequestTicketHash`` ⇄ 4768 ``ResponseTicket`` — two differently named fields. (The earlier guess
``ResponseTicketHash`` for 4768 was wrong; using it would orphan every legitimate 4769 and flag all tickets
golden.) They live in one place so the correction is shared by the synth emitter and this detector. See
``range/kerberos-ticket-hash/FINDINGS.md``.
"""

from __future__ import annotations

# CONFIRMED against a real patched Windows Server 2025 DC capture (2026-07-30, DomainMode Windows2025Domain).
# The names are ASYMMETRIC across events (see module docstring). Golden/PtT join: 4769.RequestTicketHash ⇄ 4768.ResponseTicket.
REQUEST_TICKET_HASH = "RequestTicketHash"     # on 4769 — the presented TGT's hash (the join key the detector matches)
RESPONSE_TICKET_HASH = "ResponseTicket"       # on 4768 — the issued TGT's hash (NOTE: no "Hash" suffix, unlike the 4769 fields)
SERVICE_TICKET_HASH = "ResponseTicketHash"    # on 4769 — the issued *service* ticket's hash (member-side/silver work; unused by the golden/PtT join)


def _eid(e: dict) -> str:
    return str(e.get("EventID", ""))


def detect_ticket_attacks(events: list[dict]) -> list[dict]:
    """Detect Golden / Pass-the-Ticket over a 4768+4769 stream (aggregate ALL DCs). Returns a verdict per
    suspicious 4769: ``{kind, tier, account, ip, evidence}`` where ``kind`` ∈ {golden, pass-the-ticket,
    possible-golden} and ``tier`` ∈ {hash, metadata}. A benign 4769 (hash matched, same host; or, on the
    metadata tier, an account that has a TGT) yields no verdict — and a PtT on an unpatched DC yields no
    verdict by design (NONE, not a false pass)."""
    e4768 = [e for e in events if _eid(e) == "4768"]
    e4769 = [e for e in events if _eid(e) == "4769"]

    issued = {}                                            # Response ticket hash -> issuing record (host/account)
    for e in e4768:
        h = e.get(RESPONSE_TICKET_HASH)
        if h:
            issued.setdefault(h, {"ip": e.get("IpAddress"), "account": e.get("TargetUserName")})
    accounts_with_tgt = {e.get("TargetUserName") for e in e4768}

    verdicts = []
    for e in e4769:
        acct, ip = e.get("TargetUserName"), e.get("IpAddress")
        req = e.get(REQUEST_TICKET_HASH)
        if req:                                            # ── hash tier (patched DC) ──
            if req not in issued:
                verdicts.append({"kind": "golden", "tier": "hash", "account": acct, "ip": ip,
                                 "evidence": "4769 presents a TGT whose hash was issued by no 4768 on any DC "
                                             "→ forged TGT (Golden)"})
            elif issued[req]["ip"] != ip:
                verdicts.append({"kind": "pass-the-ticket", "tier": "hash", "account": acct, "ip": ip,
                                 "evidence": f"TGT issued to {issued[req]['ip']} is presented from {ip} "
                                             "→ ticket reused across hosts (Pass-the-Ticket)"})
            # else: matched hash, same host → benign
        else:                                              # ── metadata tier (unpatched DC, no hashes) ──
            if acct not in accounts_with_tgt:
                verdicts.append({"kind": "possible-golden", "tier": "metadata", "account": acct, "ip": ip,
                                 "evidence": "service-ticket request with no TGT issuance (4768) seen for the "
                                             "account → possible forged TGT; LOW warrant (S4U / cross-DC / "
                                             "collection-gap can cause this). PtT is undetectable without hashes."})
            # else: account has a TGT → cannot distinguish benign from PtT without hashes → NONE
    return verdicts


def detect_ticket_attacks_synth(*, seed: int = 1, patched: bool = True, days: int = 5) -> dict:
    """Build the synth-enterprise timeline with the ticket-forgery campaigns, project to events with
    (``patched``) or without (un-patched DC) the ticket-hash fields, and run :func:`detect_ticket_attacks`.
    Returns the verdicts plus the ground-truth labels so recall/FP are checkable."""
    from detection.synth.emit import labeled_events
    from detection.synth.inventory import build_inventory
    from detection.synth.timeline import build_timeline

    inv = build_inventory(seed=seed)
    acts = build_timeline(inv, seed=seed, days=days, include_ticket_attacks=True)
    pairs = labeled_events(acts, inv, ticket_hashes=patched)
    events = [e for e, _ in pairs]
    verdicts = detect_ticket_attacks(events)
    labels = [lab for _, lab in pairs]
    return {"patched": patched, "seed": seed, "n_events": len(events),
            "n_labeled_attacks": sum(1 for lab in labels if lab and (lab.startswith("golden:") or lab.startswith("ptt:"))),
            "verdicts": verdicts,
            "kinds": sorted({v["kind"] for v in verdicts}),
            "tiers": sorted({v["tier"] for v in verdicts})}
