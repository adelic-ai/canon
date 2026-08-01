# Kerberos ticket-hash test range

A disposable two-VM Azure AD lab that **manufactures a real patched-DC Kerberos
capture** — real Security 4768/4769/4624 events carrying the v2 *Ticket
Information* hash fields, plus injected golden / silver / pass-the-ticket
attacks — to do two things the synthetic generator structurally cannot:

1. **Confirm the field names.** The raw `<Data Name=…>` element names for the
   ticket hashes are a `PROVISIONAL` guess in
   `packages/detection/src/detection/kerberos_tickets.py`. Script 06 prints the
   real ones.
2. **Validate the detector on real telemetry.** Run the existing
   `detect_ticket_attacks` over the captured events and confirm the
   patched→hash-tier vs unpatched→metadata-tier behaviour holds on real data,
   not just synth.

This is the "real capture" the [Kerberos state-table
page](../../web/detection/kerberos_state_table.html) has been gated on.

## Cost & footprint

Two `Standard_B2s` VMs (2 vCPU / 4 GB). Running a few hours ≈ a few dollars,
inside the Azure free account's $200 / 30-day credit. Windows licensing is
included in Azure compute. **`terraform destroy` when done** — the whole thing
is disposable (`disposable = true` tag).

## Prereqs

- Azure account (`az login` working) — free tier is fine.
- Terraform ≥ 1.5, Azure CLI.
- A Microsoft Remote Desktop client on the Mac.
- Offensive tooling **staged by you** in `C:\Tools` on mbr01 (compile GhostPack
  Rubeus; mimikatz binary). Not shipped here.

## Run order

```
# 0. infra
cd terraform
cp terraform.tfvars.example terraform.tfvars     # fill operator_ip + admin_password
terraform init && terraform apply                # ~10-15 min; prints RDP commands

# 1-2. DC (RDP to dc_public_ip)
scripts/01-promote-dc.ps1        # promote corp.local, reboots
scripts/02-enable-auditing.ps1   # patch + Kerberos auditing + lab principals

# 3. member (RDP to member_public_ip)
scripts/03-join-member.ps1       # join corp.local, reboots

# --- pick ONE run id and thread it through provenance + attacks + capture ---
#     e.g. RUNID=20260731-001

# 3b. provenance (dc01 AND mbr01) — records the patch level = the independent variable
scripts/collect-provenance.ps1 -RunId $RUNID

# 4. baseline (mbr01, as CORP\alice)
scripts/04-baseline-traffic.ps1  # benign 4768/4769/4624 — the clean control

# 5. attacks (mbr01 + dc01) — LAB ONLY. Stamps the ground-truth action ledger.
scripts/05-attacks.ps1 -RunId $RUNID   # golden / silver / pass-the-ticket

# 6. capture (dc01, then mbr01)
scripts/06-export-and-verify.ps1 -RunId $RUNID  # EVTX + JSONL + prints real hash field names

# 7. validate (back on the Mac) — everything is under C:\capture\run-$RUNID
python scripts/evtx_to_events.py run-$RUNID/dc01-events.jsonl run-$RUNID/mbr01-events.jsonl
```

This is a **pre-registered falsifier experiment** — read
[`HYPOTHESIS.md`](./HYPOTHESIS.md) (claims + nulls, written before the capture)
first, and record the verdict in [`FINDINGS.md`](./FINDINGS.md) after.

## What you get back

- `*-security.evtx` — archival real capture.
- `*-events.jsonl` — flattened events for the detector.
- The **confirmed hash field names** → set them in `FIELD_MAP`
  (`evtx_to_events.py`) and in `kerberos_tickets.py`; the `PROVISIONAL` comment
  goes away.
- A real-telemetry detector run: golden + PtT at the hash tier, silver at the
  member-side service frontier, and a clean baseline with no false positives —
  the same result now stands on a real Windows capture, not just synth.

## Safety

The NSG opens RDP/WinRM to **your IP only**; the domain is disposable; the
attack script refuses to run without a typed `LAB` confirmation and adds a
Defender exclusion only for `C:\Tools`. Do not attach this to anything real, and
`terraform destroy` when finished.

## Teardown

```
cd terraform && terraform destroy
```
