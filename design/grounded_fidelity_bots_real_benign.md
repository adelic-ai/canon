# Two-sided fidelity on a REAL benign background (BOTS v3) — corpus-wide FP + causal-labeled recall

**Status:** validation result, 2026-06-21. The first two-sided detection-fidelity measurement on a **real
benign background** (vs the synthetic faker / regime-bounded battery results). Answers the population-frontier
question for the **rule detectors**: do they catch real attacks while staying clean on real benign?
**Data stays local** (`~/data/bots-v3/...`, `~/data/otrf-security-datasets/...`); only this note is committed.
**Relates to:** [[cross_check_validation_kerberos]] (the synthetic-only predecessor), the catch-set grounding
result, [[project_fidelity_scorecard]], the engine/workspace boundary (data outside the repo).

## Setup — real benign + causally-labeled attack

- **Benign background:** BOTS v3 Sysmon, EID1 (process creation): **3616 events**, 145 distinct images, 8
  hosts, ~1 day. Extracted from the Splunk index journals (`gzip` — BSD `zcat` silently fails on `.gz`).
  Honest status: **benign-by-absence** (real capture, not certified benign) — the FP count below is an
  **upper bound**.
- **Labeled attack:** the OTRF `LSASS_campaign_03` comsvcs rundll32 MiniDump **spawn** (EID1), 1 event —
  `rundll32.exe … comsvcs.dll MiniDump 628 …`. **Causal label** (it IS the dump LOLBin executing), not a
  judgment label — so testing recall on it is non-circular.
- **Rules:** all evaluable Sigma `process_creation` rules — **1613**.
- Channel note: BOTS Sysmon is EID1/EID3-heavy; **EID8/EID10 ≈ absent** (1/0). So the EID10
  ProcessAccess comsvcs detection has **no FP surface here** — this is an EID1 (process-creation) result only.

## False-positive side — corpus-wide, the cheap broad measurement

A benign background is detector-agnostic: it is an FP surface for **every** rule at once. Over 3616 real
benign events:

- **1583 / 1613 rules (98%) never fire** — clean on this real surface.
- **30 rules false-positive.** Lopsided:
  - `Elevated System Shell Spawned` — **969 / 3616 = 27%** of the real benign surface. Essentially unusable
    untuned; only real admin activity surfaces this, which synthetic benign cannot fake.
  - tail: `Recon … Piped To Findstr` (37), `Non Interactive PowerShell` (15), `Base64 PowerShell` (12),
    `HackTool - Empire Launch Parameters` (10), `Unusually Long PowerShell CommandLine` / `Net WebClient
    Casing` (9 each), recon rules (4–6).

## Recall side — narrow, bounded by labeled attacks

**4 of 1613** rules catch the comsvcs EID1 spawn: `Process Memory Dump Via Comsvcs.DLL`, `Potentially
Suspicious Rundll32 Activity`, `LSASS Dump Keyword In CommandLine`, `Suspicious SYSTEM User Process Creation`.

## Two-sided — the product (catch the real attack AND clean on real benign)

- **3 CLEAN catchers** (catch + 0 FP on 3616 real benign): `Process Memory Dump Via Comsvcs.DLL`,
  `Potentially Suspicious Rundll32 Activity`, `LSASS Dump Keyword In CommandLine`. These are the high-quality
  detections — precise on real telemetry.
- **1 noisy catcher:** `Suspicious SYSTEM User Process Creation` (catches it, but 2 FP — too broad on benign
  SYSTEM processes).

So the rules can be **ranked by real-world precision**, not synthetic — the thing the synthetic faker could
not give.

## The asymmetry (the load-bearing structural finding)

Real benign yields a **broad** FP scorecard (1613 rules, one pass) **cheaply**; **recall stays narrow** (one
labeled attack here — as many as we inject). The benign surface is shared across the whole corpus; the attack
labels are not. This is why the next data move is the **dataset generator** (synthcyber + Fable 5 authoring
causally-labeled attacks) — it widens the *narrow* side, while a real capture (BOTS) already widened the
broad side.

## Honest caveats (all stated, none pretended away)

- **Benign-by-absence** — the 969 `Elevated System Shell` fires are almost certainly real admin activity, but
  we cannot certify none are undetected attacks; FP is an **upper bound**. (969 is far too high to be attacks,
  so the *finding* holds.)
- **One corpus** (BOTS, 8 hosts, 1 day) — FP rates are environment-specific, not universal.
- **EID1 only** — the statistical battery (fan-out, EID10/4769) is NOT exercised here; this is the rule /
  structural detector axis. The battery on a real population still needs differently-channelled data.
- **Recall n=1 attack** — one causal instance; broad recall needs the generator.

## What this advances

The population frontier is **partially crossed**: rule-detector two-sided fidelity on a real benign
background is done, and it produces a real, rankable precision signal (3 clean catchers) plus a fileable FP
finding (`Elevated System Shell` at 27% — a better SigmaHQ-contribution candidate than the dedup angle, with
the one-corpus caveat). The statistical battery on a real population, and broad recall, remain open — both
gated on differently-shaped data (other channels / the generator).
