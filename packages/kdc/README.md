# kdc — a minimal Kerberos KDC with the state table built in

A POC / ground-truth generator. Real KDCs are stateless — they validate a
presented ticket cryptographically and keep **no** registry of what they issued,
which is exactly why golden/silver forgery works. This one **keeps the ledger**,
so the invariant a real KDC can't enforce becomes checkable:

> a presented ticket ⊢ a prior issuance of it

That necessity edge is the entailment rule, **derived from the protocol state
machine** rather than guessed. See `web/detection/kerberos_state_table.html` and
`web/detection/three_entailments.html` for the framing.

## What it does

- **The exchanges as transitions** (`kdc.domain.Domain`): `as_req` → 4768,
  `tgs_req` → 4769, `ap_req` → 4624. Each records issuance in the ledger and
  emits telemetry carrying the ticket hashes (the POC analogue of the Windows v2
  4768/4769 ticket-hash fields).
- **Forgeries** (`kdc.attacks`): `golden_ticket` (forged TGT under the stolen
  krbtgt key, no AS-REQ), `silver_ticket` (forged service ticket under the stolen
  service key, never touches the KDC). Both **validate cryptographically** — the
  KDC/service accept them — the whole point.
- **The SIEM-side detector** (`kdc.detect.classify`): reconstructs the issued-set
  from telemetry only (no access to the in-memory ledger) and classifies each
  presentation as **CONFIRMED / GAP / NONE / CONTEXT-DIVERGENCE**. Golden = a 4769
  presenting a TGT hash with no issuing 4768. Silver = a 4624 service logon with
  no issuing 4769 (the member-side frontier). Pass-the-ticket = issued-but-relocated.

## Honest scope (v0)

Surrogate crypto (`kdc.crypto`): a key is `sha256(password)`, "sealed under a key"
is an HMAC tag — faithful enough that you can't forge a valid seal without the key
and the KDC can validate without issuance memory, which is all the state machine
needs. **Not** RFC 4120: no real AES/RC4, no PAC, no cross-realm. A logical clock
(not wall-clock) keeps runs deterministic. Next: wire MIT krb5 as a ground-truth
oracle; derive canon's Kerberos detection rules from the state table.

## Run

```
uv run pytest packages/kdc/tests -q
```
