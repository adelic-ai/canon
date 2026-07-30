# FINDINGS — Kerberos ticket-hash detector on real patched-DC telemetry

**Date:** 2026-07-30
**Status:** H1 **confirmed**; H2 baseline (no-FP) **confirmed on-box**; H2 positive golden/PtT **pending** (needs attack tooling on a joined member).
**Verdict:**
- **H1 (field names): CONFIRMED, with a correction.** A patched WS2025 DC *does* emit ticket-hash fields on 4768/4769, and they join — but the names are **asymmetric**, and our guess for 4768 was wrong: 4768 uses **`ResponseTicket`** (not `ResponseTicketHash`); 4769 uses **`RequestTicketHash`** + **`ResponseTicketHash`**.
- **H2 (detector): baseline confirmed on real telemetry.** The golden-ticket rule (4769 `RequestTicketHash` with no issuing 4768 `ResponseTicket`) yields **0 false positives** on real benign traffic. Positive golden/PtT detection not yet exercised.

**Environment:** Azure westus2, Windows Server 2025 Datacenter (Gen2), image `2025-datacenter-g2` version `26100.33158.260711` (~Jul 2026 build), DomainMode `Windows2025Domain`, domain `corp.local`, DomainSID `S-1-5-21-2085479354-2585467852-1395980066`.
**Repo state:** canon field-name correction applied (see below); range @ commit `f48782c` + this run's edits.

> Pre-registration: [`HYPOTHESIS.md`](./HYPOTHESIS.md).

## H1 — Field names (the confirmation)

Real `<Data Name=…>` fields carrying ticket hashes, read off live events:

| event | field | holds |
|---|---|---|
| **4768** (AS-REP, TGT issued) | **`ResponseTicket`** | SHA-256 of the issued TGT (base64, 32B) |
| **4769** (TGS-REQ, service ticket) | **`RequestTicketHash`** | SHA-256 of the **presented TGT** (the join key) |
| **4769** | **`ResponseTicketHash`** | SHA-256 of the issued service ticket |

| role | provisional guess | real field name | verdict |
|---|---|---|---|
| presented TGT (4769) | `RequestTicketHash` | `RequestTicketHash` | ✅ correct |
| issued TGT (4768) | `ResponseTicketHash` | **`ResponseTicket`** | ❌ **wrong — no "Hash" suffix** |

**Join verified:** multiple 4768 `ResponseTicket` values equal 4769 `RequestTicketHash` values for the same TGTs on benign traffic → `4769.RequestTicketHash ⇄ 4768.ResponseTicket` is a real cross-event join.

**Why the correction matters:** had we shipped the guessed `ResponseTicketHash` for 4768, the issued-TGT registry would be empty and *every* legitimate 4769 would look "issued by no 4768" → 100% false-positive golden. Only a real capture surfaces the asymmetric naming.

**Action taken (canon):** `detection/kerberos_tickets.py` — `RESPONSE_TICKET_HASH = "ResponseTicket"` (was `"ResponseTicketHash"`); added `SERVICE_TICKET_HASH = "ResponseTicketHash"` for the 4769 issued-service-ticket hash (member-side/silver, unused by the golden/PtT join); docstring updated to CONFIRMED + the asymmetry. `synth/emit.py` — 4769 issued-service field now uses `SERVICE_TICKET_HASH`. `FIELD_MAP` in `evtx_to_events.py` stays empty (the corrected constants now equal the raw Windows names). Affected tests (`test_kerberos_tickets`, `test_synth_emit`) pass.

## H2 — Detector on the real capture

Windows build at capture: `26100.33158.260711`, DomainMode `Windows2025Domain` → **hash tier** (fields present).

| action | expected | observed | pass? |
|---|---|---|---|
| baseline (benign 4768/4769) | no findings / 0 FP | **orphans=0** over 19 presented vs 11 issued (on-box golden-rule check) | ✅ |
| golden ticket | `golden` / hash | _pending — needs Rubeus on a joined member_ | — |
| pass-the-ticket | `pass-the-ticket` / hash | _pending_ | — |
| silver ticket | not flagged (blind spot) | _pending_ | — |

The baseline was checked on-box in PowerShell (the detector's golden rule reimplemented: for each 4769 `RequestTicketHash`, is there a matching 4768 `ResponseTicket`?). 0 orphans = no false golden on real benign traffic. The **positive** golden/PtT cases and a run of the actual `detect_ticket_attacks` over an exported real capture remain — they need the member joined and Rubeus/mimikatz staged.

## Analysis

The primary, uniquely-capture-dependent question (H1) is answered: the v2 ticket-hash telemetry is real on WS2025, it joins, and the field naming is asymmetric in a way that would have broken the detector had it shipped on the guess. The correction is a two-string change in one file, now made. The baseline no-FP result gives the first real-telemetry evidence for H2; positive-detection remains.

## Conclusion

A patched Windows Server 2025 DC emits joinable Kerberos ticket-hash fields — `4768.ResponseTicket ⇄ 4769.RequestTicketHash` — and canon's detector now reads the real (asymmetric) names instead of a wrong guess; the golden rule is clean on real benign traffic.

## Next steps

- Positive H2: join `mbr01`, stage Rubeus/mimikatz, run golden/silver/PtT (`05-attacks.ps1`), export (`06`), run the real `detect_ticket_attacks` (`evtx_to_events.py`).
- Back-port the confirmed field names into the Splunk/Sentinel ticket-integrity pages (they reference the display labels, not the raw names).
- `collect-provenance.ps1` was not run this session — grab exact build + KBs on the next run for the provenance bundle.
