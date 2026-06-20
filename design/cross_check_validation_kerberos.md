# Fan-out cross-check validation on faker-kerberos — the first positive battery result

**Status:** validation result, 2026-06-20. The positive counterpart to [[cross_check_validation_otrf]]
(which was negative — *wrong data*). Reproduced via `detection.fanout.load_kerberos_events` +
`detect_fanout` / `detect_by_distinct_count` over `~/data/faker-kerberos/v1/export.csv`.
**Relates to:** [[cross_check_validation_otrf]] (the matched-measure-to-phenomenon lesson),
[[project_feature_engineering_is_a_product]] (revises "entropy unproven vs baseline"),
[[project_canon_restart]] (closes the #1 open gap: cross-check operational value).

## Question

The #1 open gap: does a battery cross-check (`distinct ⟷ entropy`) `both`/disagreement — or its agreement —
coincide with a *real labeled* attack? OTRF couldn't answer it (LSASS is a *structural* signature, not a
fan-out). `faker-kerberos` is the **right data**: one account → many distinct service tickets *is* the
Kerberoast fan-out, and it's labeled.

## Setup

- Data: `faker-kerberos` (synthetic, labeled — `export.truth.json` names the attacks). 4 labeled
  Kerberoasters (christopher.hall, debra.gardner, jill.rhodes, maria.montgomery). 25,971 events.
- Binding: entity = `Account_Name`, value = `Service_Name` (the Kerberoast fan-out).
- Detectors: `detect_fanout` (conformal entropy, α=1e-3) vs `detect_by_distinct_count` (the trivial baseline
  threshold).

## Result — grain is load-bearing

```
grain     ENTROPY (conformal)        DISTINCT-COUNT baseline
per-day   flagged 0,  recall 0/4     thr10: 4/4 +21 FP   · thr20: 0/4   (burst diluted; entropy finds no outlier)
per-hour  flagged 6,  recall 4/4     thr10: 4/4 +3  FP   · thr20: 0/4   (burst isolated)
per-10m   flagged 6,  recall 4/4     thr10: 4/4 +2  FP   · thr20: 0/4
```

Three findings:

1. **The fan-out detector works on the right data** — recall **4/4** on labeled Kerberoasters (at a
   burst-matching grain). Contrast OTRF, where fan-out was the wrong phenomenon and the payload was
   statistically indistinguishable from benign.
2. **Conformal entropy beats the distinct-count baseline on *robustness* — the first positive result for the
   sophisticated primitive.** Entropy catches 4/4 **threshold-free**; distinct-count's recall **swings 4→0
   between thr=10 and thr=20** (too low → false positives, too high → misses the burst — a brittle hand-tuned
   cut). This *revises* the standing "entropy is unproven vs distinct-count" finding: entropy's edge is not
   higher peak recall (both reach 4/4 at the right grain+threshold) — it is **not needing a magic
   threshold** (the conformal / distribution-free promise, finally shown earning its keep).
3. **Cross-check operational value demonstrated.** At the right grain entropy and distinct **agree** on the 4
   attacks (corroboration → confidence), and their *disagreement* exposes distinct's threshold-brittleness.
   The `both` finally tracks something real — unlike OTRF, where the disagreement was dominated by benign.

## Caveats (honest)

- **Grain is the load-bearing parameter** (the c_bin-collapse sensitivity, concrete): per-day dilutes the
  burst to nothing (entropy 0/4); only a grain matching the attack timescale works. A real deployment must
  pick/scan the grain.
- **Synthetic data** (`faker-kerberos`), **n=4 attacks** — small and not real telemetry. The real-data
  confirmation on `splunk/attack_data` T1558.003 was **attempted and did NOT close the caveat** — see
  [[cross_check_validation_t1558003_real]]. That capture is a pure-attack burst (159 events, 2 machine
  accounts, no benign background), so conformal is underpowered and distinct-count wins — the *opposite* of
  this result. It doesn't refute the finding; it **bounds the regime**: conformal-beats-threshold holds on a
  **large standing population with benign background** (as here), not on isolated attack captures. Closing the
  caveat needs real telemetry *with* a benign population (atomic-red-team captures structurally lack it).

## Conclusion

The cross-check / battery **is** validatable — on data that *exercises the phenomenon*, at a grain that
*matches the attack timescale*. The OTRF negative was a data mismatch, not a verdict on the method; here, on
matched data, conformal entropy is threshold-robust where the baseline is brittle, and the cross-check
agreement is real corroboration. This is the first time the battery's value has been shown — caveated by
grain-sensitivity and synthetic-only, with the real-data confirm one fetch away.
