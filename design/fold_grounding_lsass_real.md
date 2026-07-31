# The first real-data grounding of the partial-kill-chain fold

**Status:** validation result, 2026-07-31. The composition-layer counterpart to the
atom-level real-data results ([[cross_check_validation_kerberos]] fan-out; the Kerberos
ticket-hash golden in `range/kerberos-ticket-hash/FINDINGS.md`; the comsvcs+lsass subgraph
in `experiments/lsass_subgraph_detection.py`). Reproduced via
`experiments/fold_grounding_lsass_real.py` over the real OTRF `LSASS_campaign_03` capture.
**Relates to:** [[kill_chains_as_entity_path_analysis]] (completeness × abnormality — the
frame), `detection/partial_chain.py` + `detection/completeness.py` + `detection/anchor_posterior.py`
(the fold under test), `detection/hmm.py` (the decode gate).

## Question

Everything real-data validated so far has been an **atom** — a single detector firing correctly
on real telemetry (Kerberos golden orphan-hash; the comsvcs⊢lsass subgraph). The **fold** — the
composition that turns a partial, time-ordered technique sequence into a scored path toward a
crown jewel, then into a decaying per-anchor posterior — was tested only on synthetic models.

Does the fold — `compose_partial_chain` (completeness / reach / frontier / internal-gaps) plus
`AnchorPosterior` (decaying log-odds) — behave on **real, linked atom firings** the way it does
on synth? Specifically: does it escalate monotonically, predict the frontier, decay when quiet,
and expose an entailed-but-missing GAP?

## Setup

- **Data:** OTRF Security-Datasets `LSASS_campaign_03` (real Sysmon, 41,954 events, host
  `PRD01.pandalab.com`). Staged locally at `~/data/otrf-security-datasets/`.
- **The chain — one actor, one host, one `ProcessGuid`** (`{…-3409-…}`, `winx64_payload.exe` =
  Pupy RAT). Coreference is solved by ProcessGuid, so this **isolates the fold** and deliberately
  does *not* stress the identity mystery:

  | atom | tactic (decoded) | technique | real event | time |
  |---|---|---|---|---|
  | A1 | execution | T1204 | Sysmon EID 1 — spawn `winx64_payload.exe` | 15:56:49 |
  | A2 | command-control | T1105 | Sysmon EID 11 — drop `qfhaer.dll` | 15:58:11 |
  | A3 | **credential-access** (crown jewel) | T1003.001 | Sysmon EID 10 — LSASS read `0x1410` | 15:58:43 |

- **Model:** tactic transitions + emissions built from the **real Attack-Flow corpus**
  (`build_model` / `emission_model`) — 40 flows, 145 transitions. Nothing synthetic except the
  analyst naming the crown jewel (`credential-access` on PRD01) and the target path.

## Result — the fold escalates, predicts, decays, and gaps

```
after A1 (execution        ): completeness=0.33 reach=0.33 complete=False frontier=command-control  | P(anchor)=0.019
after A2 (command-control  ): completeness=0.67 reach=0.67 complete=False frontier=credential-access | P(anchor)=0.220
after A3 (credential-access): completeness=1.00 reach=1.00 complete=True  frontier=None             | P(anchor)=0.991
12h later, no new evidence :                                                                          P(anchor)=0.034
```

Four fold behaviors, all on real linked atoms:

1. **Monotone escalation.** The per-anchor posterior climbs `0.019 → 0.220 → 0.991` as the chain
   assembles toward the crown jewel — the decaying log-odds accumulator folding one atom at a time.
2. **Frontier prediction.** After A1 the fold names `command-control` as the next milestone; after
   A2, `credential-access` — each correct against what actually came next.
3. **Decay.** With no fresh evidence, the posterior falls `0.991 → 0.034`, back toward the 0.01
   base rate — old pressure forgotten.
4. **The GAP signature.** Drop the middle atom (simulated telemetry gap): `reach=1.00,
   completeness=0.67, internal_gaps=('command-control',)`. Reach > completeness ⇒ the jewel was
   reached but a lead-up step is **entailed-but-missing** — a GAP to hunt, not a NONE. The
   entailment-gap machinery fires on real data.

**Bonus — the corpus model corrected a human label.** T1105 was hand-labeled `defense-evasion`;
the Attack-Flow decode put it under `command-control`, where ATT&CK actually places Ingress Tool
Transfer. The decode is load-bearing, not decoration — it overrode the analyst.

## Caveats (honest)

- **Single-host, single-process micro-chain.** Coreference is trivial (ProcessGuid), so this does
  **not** test cross-host lateral movement toward a *network* crown jewel, and does **not** stress
  the identity mystery. That is the next real capture — and the local APT sims (`splunk-attack-data`
  FIN7 / APT29) are empty placeholders, so it needs a fetch.
- **Not a calibrated probability.** `AnchorPosterior` sums LLRs assuming conditional independence
  (its own docstring flags this) → `P=0.991` is an **upper-bound pressure signal**, not a calibrated
  P(compromise). `abnormality` was stubbed at `1.0` (no per-account baseline computed), so the score
  is completeness × reach only.
- **Crown jewel + target path are analyst choices.** Legitimate (the analyst names the jewel), but
  not derived from data.

## Conclusion

The partial-kill-chain fold — completeness / reach / frontier / GAP plus the decaying anchor
posterior — **runs correctly on real, ProcessGuid-linked atom firings from a real capture**, and
the tactic decode is grounded in the real Attack-Flow corpus (which corrected a wrong human label).
This is the first time the *composition layer*, not just an atom, has been shown on real data. The
thesis-level claim it does **not** yet reach — cross-host, identity-fragmented chains toward a
network crown jewel — is a **capture** gap, not a code gap: the fold works; the harder data is the
frontier.
