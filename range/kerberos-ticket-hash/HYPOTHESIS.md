# Experiment: Kerberos ticket-hash detector on real patched-DC telemetry

**Date registered:** 2026-07-30 (pre-capture — written before any real event is seen)
**Status:** registered / not yet run
**Repo state:** canon @ `<fill: git rev-parse HEAD>`; range untracked (see below)
**Environment:** Azure, 2× Windows Server 2025 (Gen2) — `dc01` (DC, corp.local) + `mbr01`
**Detector under test:** `packages/detection/src/detection/kerberos_tickets.py::detect_ticket_attacks`

This is a **falsifier**, in the house style of `~/dev/experiments`: the claims,
the nulls, and the expected per-action outcomes are committed **before** the
capture. The capture is then allowed to refute them.

---

## Two claims

### H1 — Mechanism / field names (the sharp one)

**Claim.** A Windows Server 2025 DC patched to ≥ the Jan-2025 CU, with Kerberos
auditing enabled, emits ticket-hash fields inside Security events 4768 and 4769,
under stable `<Data Name=…>` element names that provide a cross-event join
(the 4769 *request* hash equals the issuing 4768's *response* hash for a
legitimately issued ticket).

**Null (what refutes H1).** After `06-export-and-verify.ps1` on a confirmed-
patched DC with auditing on: **no hash-bearing `<Data Name=…>` fields appear on
4768/4769**, OR they appear but do not join (a benign ticket's 4769 request hash
matches no 4768 response hash). Either outcome means the entire **hash tier** of
the detector rests on a Windows feature that does not behave as the code assumes.

**Decision rule.**
- Hash fields present **and** they join on the benign baseline → H1 confirmed.
  Record the real element names; set them in `evtx_to_events.py::FIELD_MAP` and
  in `kerberos_tickets.py` (retire the `PROVISIONAL` comment).
- Hash fields absent/non-joining → H1 refuted. Record the exact build + KBs,
  check for a KDC ticket-info logging setting, and downgrade the story: the
  detector is **metadata-tier only** on this build, PtT undetectable. That is a
  real, publishable finding — not a failure to hide.

### H2 — Detector behavior on the real capture

**Claim.** Run over the real capture, `detect_ticket_attacks` yields:

| action (ground truth) | expected verdict | tier | note |
|---|---|---|---|
| **baseline** (benign AS/TGS/logon) | *no findings* | — | 0 false positives is the bar |
| **golden ticket** | `golden` | hash | forged TGT: 4769 request hash issued by no 4768 |
| **pass-the-ticket** | `pass-the-ticket` | hash | real TGT, 4769 source IP ≠ issuing 4768 IP |
| **silver ticket** | *not flagged* (by design) | — | **known blind spot**: 4624 with no 4769; the detector has no `silver` kind. Recorded as an expected non-detection, NOT a miss. |

**Null (what refutes H2).** Any of: a false positive on the benign baseline; a
missed `golden` when hashes are present; a missed `pass-the-ticket` when hashes
are present. (Silver being unflagged is the *pre-registered expectation*, not a
refutation — the point is the detector degrades honestly, per canon's
no-completion-theater rule.)

**Decision rule.**
- Golden + PtT caught at the hash tier **and** baseline clean → H2 confirmed on
  real telemetry (upgrades "validated in simulation" → "validated on real DC").
- Otherwise → H2 refuted or partial; write exactly which cell failed and why.

H2 is conditional on H1: if hashes are absent, H2 is evaluated at the metadata
tier instead (golden → `possible-golden` LOW; PtT → expected miss).

---

## Ground truth is independent of the detector

Per the integrity rule (and ChatGPT's §9): the expected-outcomes table above is
authored here, pre-capture, from the *actions we execute* — not derived from
Canon's output. Each attack action in `05-attacks.ps1` must emit a structured
start/stop marker (action id, kind, source host, principal, timestamps) so the
capture can be aligned to ground truth without trusting the detector to label
its own test. `evaluate` (by eye for run 1) compares this table to the verdicts.

## Provenance the run must capture

The patched-vs-unpatched state is the experiment's **independent variable**, so
it is recorded, not assumed. `collect-provenance.ps1` (run on both hosts before
capture) records: Windows build number, installed KBs/hotfixes, `auditpol`
state, time-sync status, image publisher/offer/SKU/version. Plus: canon commit,
Terraform + provider versions, script SHA-256s, attack-tool versions, capture
start/end. These land in the run directory alongside the EVTX.

## Reproducibility checklist (fill at run time)

- [ ] canon commit SHA recorded; range committed or SHA-stamped
- [ ] `collect-provenance.ps1` output captured for dc01 + mbr01 (build + KBs)
- [ ] image SKU + exact version recorded (not just "2025")
- [ ] script checksums recorded
- [ ] action start/stop markers emitted and aligned to ground truth
- [ ] capture stored under a unique run id (not overwriting `C:\capture`)
- [ ] `terraform destroy` confirmed, no residual Azure resources

## Deferred (not run 1)

Dockerized evaluator + `evaluate.py`; the generalized `range/common/` framework
and multi-scenario fleet; experiment-contract → ATT&CK/D3FEND/STIG wiring. Let
these fall out of 2–3 real runs — see the ChatGPT note (§3, §12) for the vision,
but not before the first capture answers H1 and H2.
