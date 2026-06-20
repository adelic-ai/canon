# Catch-set grounding pivot — handoff brief (Maude)

**Date:** 2026-06-20. **For:** the second instance ("Maude"), opened at `~/canon`. **Goal:** produce
**catch-set grounding** — the behavioral ground truth (which rules actually catch which labeled instances)
that the whole structural stack (rule lattice, tag claims, dedup) is a proxy for. This is the keystone.

## Coordination (avoid stepping on the main instance)

- Work on your **own branch**: `git switch -c feat/catch-set-grounding`. The main instance stays on
  `feat/sigma-treatment-pipeline` doing the structural lattice/product work — **do not** touch
  `detection/rule_lattice.py` or `detection/atom_implication.py` (those are the main instance's).
- **You own:** `packages/synthcyber/` (scenarios), new `packages/detection/src/detection/catch_set.py`,
  `packages/detection/src/detection/fidelity_scorecard.py` (extend), and `~/data/`.
- **Never delete branches** (the user does that). Commit + push your branch; do not merge to `main`.
- **All telemetry stays in `~/data/`, never committed** (engine/workspace boundary; data is path-ref'd /
  skip-if-absent).

## What's already staged in ~/data (don't re-fetch)

`otrf-security-datasets/LSASS_campaign_03` (1 OTRF set, T1003.001), `faker-kerberos` (Kerberos — the *right*
data for the fan-out cross-check), `flaws-cloudtrail` (AWS), `bots-v3` (Splunk BOTS, scenario-level),
`attack-flow-corpus` (campaign trajectories). 157 GB free.

## Target list — fetch to ~/data/ (the Windows per-technique gap)

```sh
# 1. FULL OTRF — we have 1 of hundreds; JSONL, _metadata.yaml ATT&CK labels (GPL-3.0). Biggest win.
git clone --depth 1 https://github.com/OTRF/Security-Datasets ~/data/otrf-security-datasets-full
# 2. EVTX-to-MITRE-Attack — 270+ per-technique, + Linux/AWS/Azure/O365. Small.   (EVTX → convert)
git clone https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack ~/data/evtx-to-mitre
# 3. EVTX-ATTACK-SAMPLES — canonical Windows per-technique corpus. Small–mid.     (EVTX → convert)
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES ~/data/evtx-attack-samples
# 4. hayabusa-sample-evtx — curated to exercise Sigma rules. Small.              (EVTX → convert)
git clone https://github.com/Yamato-Security/hayabusa-sample-evtx ~/data/hayabusa-sample-evtx
# 5. splunk/attack_data — per-T#### atomic telemetry. Large; optional (bots-v3 covers Splunk shape).
git clone --depth 1 https://github.com/splunk/attack_data ~/data/splunk-attack-data
```
Verify each `LICENSE` on clone (local research grounding is fine for all).

## Steps

1. **Convert EVTX → JSONL** (#2–#4 are `.evtx`, not JSONL like OTRF). Use `evtx_dump` (omerbenamram/evtx,
   Rust) or Chainsaw → one JSON object per record, so they match the `detection.subgraph.load_sysmon_events`
   shape. Keep the per-folder ATT&CK-technique label from the source repo's directory structure.
2. **Build `detection/catch_set.py`** — `group_by_catch_set(rules, labeled_instances)`: run every evaluable
   rule over the labeled malicious instances, record per-rule `caught_on: [instance_cid]`, then group rules by
   *identical co-caught sets* = true catch-set (behavioral) synonymy. Extend `grounded_fidelity` to return
   `caught_on` per rule (the survey noted this is the one missing return value).
3. **Run fidelity over the REAL labeled data** — `technique_fidelity` / `grounded_fidelity` per technique
   (claim-vs-catch + recall/FP). For techniques with real labeled instances, this is direct ground truth — no
   synthetic needed. Output the per-technique scorecard + the catch-set groups.
4. **Compare** the catch-set groups to the structural keys (`content_signature`, and the main instance's rule
   lattice) — does structural-related actually equal catch-related? That's the grounding result.
5. **Fill gaps with synthcyber + Fable 5** — for techniques with *no* real data: have **Fable 5** author
   `synthcyber.Scenario`s (the attack-signature events), **seeded from real attack docs** (atomic-red-team,
   campaign reports), grounded via `synthcyber.grounding.ground()` (inject into a real benign background), and
   **realism-checked against the fetched real telemetry** (does an LLM-written T#### event resemble real
   T#### events?). Fable 5 only authors; the grounding + fidelity machinery is the verifier that keeps it
   honest. Do NOT score rules against unrealistic LLM-imagined attacks — the real-data realism check is the
   guard.

## What this unlocks

Grounded catch-set → verifies tags corpus-wide, grounds the lattice edges (claimed→earned), makes dedup
behavioral, and unlocks Fable-5-as-semantic-proposer. It is the load-bearing unbuilt piece.
