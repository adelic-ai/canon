# FINDINGS — Kerberos ticket-hash detector on real patched-DC telemetry

**Date:** 2026-07-30
**Status:** H1 **confirmed**; H2 baseline (no-FP) **confirmed**; H2 **positive golden CONFIRMED** — both on-box (PowerShell rule) **and via the shipped `detect_ticket_attacks` over a real exported capture**. PtT not run (optional); silver deliberately out of scope (known blind spot).
**Verdict:**
- **H1 (field names): CONFIRMED, with a correction.** A patched WS2025 DC *does* emit ticket-hash fields on 4768/4769, and they join — but the names are **asymmetric**, and our guess for 4768 was wrong: 4768 uses **`ResponseTicket`** (not `ResponseTicketHash`); 4769 uses **`RequestTicketHash`** + **`ResponseTicketHash`**.
- **H2 (detector): baseline AND positive golden confirmed on real telemetry, via the shipped detector.** The golden-ticket rule (4769 `RequestTicketHash` with no issuing 4768 `ResponseTicket`) yields **0 false positives** on real benign traffic, and **flags a real forged golden ticket** — a forged `eviladmin` TGT (Rubeus, signed with the DSInternals-extracted krbtgt key) was used from mbr01 to read the DC's `C$`, and the detector surfaced the orphan 4769s from mbr01's IP. Confirmed two ways: (a) on-box PowerShell reimplementation of the rule → `GOLDEN orphans: 2`; (b) **canon's actual `detect_ticket_attacks`** run over the exported capture (`dc01-events.jsonl`, 1037 events, 73 hash-bearing → **HASH tier**) → **2 `golden` verdicts at the hash tier**, ip `::ffff:10.42.1.4`, evidence "4769 presents a TGT whose hash was issued by no 4768 on any DC → forged TGT (Golden)". The packaged code path reproduces the on-box result exactly.

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
| golden ticket | `golden` / hash | **2 `golden`/hash verdicts** from the shipped `detect_ticket_attacks` (and `GOLDEN orphans=2` on-box) — same forged `RequestTicketHash` (`QbgkT3sQ…HKU=`) presented from mbr01 (`::ffff:10.42.1.4`), matching **no** issued 4768 `ResponseTicket` | ✅ |
| pass-the-ticket | `pass-the-ticket` / hash | _not run (optional add)_ | — |
| silver ticket | not flagged (blind spot) | _out of scope by design_ | — |

Both baseline and positive golden were checked on-box in PowerShell (the detector's golden rule reimplemented: for each 4769 `RequestTicketHash`, is there a matching 4768 `ResponseTicket`?). Benign traffic → **0 orphans** (no false golden); the forged-golden attack → **2 orphans**, both the same forged TGT hash from mbr01's IP, with no issuing 4768 — because a forged TGT is never minted by the real KDC, so no AS-REP 4768 `ResponseTicket` exists for it. The attack itself landed: the forged `eviladmin` TGT read the DC's `C$`.

The packaged `detect_ticket_attacks` was then run over the *exported* real capture (`06-export-and-verify.ps1` → `evtx_to_events.py`, 1037 events / 73 hash-bearing → HASH tier) and produced **2 `golden`/hash verdicts** — the shipped code path reproducing the on-box result. Golden is closed both ways.

## Analysis

The primary, uniquely-capture-dependent question (H1) is answered: the v2 ticket-hash telemetry is real on WS2025, it joins, and the field naming is asymmetric in a way that would have broken the detector had it shipped on the guess. The correction is a two-string change in one file, now made. H2 is answered too: 0 false-golden on real benign traffic, and the shipped detector flags the real forged golden ticket at the hash tier.

## Conclusion

A patched Windows Server 2025 DC emits joinable Kerberos ticket-hash fields — `4768.ResponseTicket ⇄ 4769.RequestTicketHash` — and canon's detector now reads the real (asymmetric) names instead of a wrong guess. On real telemetry the shipped `detect_ticket_attacks` gives 0 false-golden on benign traffic and flags a real forged golden ticket at the hash tier.

## Next steps

- ~~Packaged-detector run~~ **DONE** — exported `dc01-events.jsonl` (via `az vm run-command`, since RDP clipboard/drive redirection were both dead this session), ran the shipped `detect_ticket_attacks`: 2 `golden`/hash verdicts, reproducing the on-box result. VMs no longer needed.
- Optional: pass-the-ticket case (`05-attacks.ps1`); silver stays out of scope (expected-not-caught blind spot).
- Back-port the confirmed field names into the Splunk/Sentinel ticket-integrity pages (they reference the display labels, not the raw names).

## Provenance gap (recorded, not fixed)

`collect-provenance.ps1` was **never run** — no hotfix/KB bundle or audit-state JSON was captured — and the range was `terraform destroy`ed after the packaged-detector run, so the DC no longer exists to query. The exact-KB provenance for this capture is unrecoverable.

**Assessed impact: low; changes no verdict.** The capture is self-certifying on the one variable provenance was meant to record (patch level): the v2 hash fields only exist in the post-Jan-2025-CU schema, so their presence *is* proof the DC is patched. The OS build (`26100.33158.260711`, image `2025-datacenter-g2`) is recorded above and maps to a specific CU by lookup; auditing-was-on is proven by the 4768/4769 events existing; time-sync is irrelevant here. The granular KB list would add reproducibility convenience, not evidence.

**Where provenance would actually have mattered — and it's a different gap:** the falsifier's contrast is patched-vs-unpatched. Only the *patched* arm was captured. The unrun, higher-value experiment is the **unpatched control** (deploy → promote → do NOT patch → capture → provenance → destroy), which would directly test H1's null (unpatched DC emits no hash fields, metadata tier). Provenance on the patched DC alone is half of a comparison whose other half was never taken. If this ever needs to be airtight for a formal writeup, capture the unpatched control — not patched-provenance.

- If a fresh provenance bundle is still wanted for its own sake, redeploy is ~1–1.5 hr (mostly Windows Update) and certifies a *new* patched DC, not this now-destroyed capture.

> **Session note (2026-07-30):** the golden attack + on-box detection above were executed in the prior session (transcript `fee00fd8`); that session was terminated mid-run by the platform Real-time Cyber Safeguards classifier (API-level block, `req_011CdY…`) before the result could be written here. This entry reconstructs it from the detection-side output.
