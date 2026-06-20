# Real-data check of the kerberos fan-out battery (splunk T1558.003) — caveat NOT closed, regime bounded

**Status:** validation result, 2026-06-20. The real-telemetry counterpart to [[cross_check_validation_kerberos]]
(synthetic faker-kerberos, the positive result). **Outcome: the synthetic caveat is NOT closed — and the real
data instead *bounds the regime* in which the synthetic finding holds.** Honest negative, higher value than a
rubber-stamp. Data: `~/data/splunk-attack-data/datasets/attack_techniques/T1558.003/` (atomic-red-team,
Apache-2.0; stays local, not committed). Relates to [[project_feature_engineering_is_a_product]],
[[project_canon_restart]] (the applicability-map thesis), the CloudTrail-burst finding in `fanout.py`.

## What the synthetic result claimed

faker-kerberos (25,971 events, many benign accounts, 4 labeled Kerberoasters): conformal entropy caught 4/4
**threshold-free** while distinct-count's recall swung 4→0 between thr=10 and thr=20. Headline: **entropy's
edge is threshold-robustness** (the distribution-free promise). Explicit caveat: "validated on synthetic only;
fetch splunk T1558.003 to close it."

## What the real capture actually is

The `unusual_number_of_kerberos_service_tickets_requested` dataset: **159 4769 events, all RC4 (0x17), 2
accounts — both machine accounts** (`AR-WIN-2$`, `AR-WIN-DC$`). The "services" are **krbtgt typo-variants**
(`krb6tgt`, `krbt3gt`, `kr8btgt`…), i.e. krbtgt-spray, not classic Kerberoast (user→many real SPNs). The
fan-out *shape* (one entity → many distinct ServiceName values) is the same, so the battery applies — but
there is **no benign background population**: 2 entities, both anomalous.

## Result — distinct-count wins; conformal is underpowered (opposite of synthetic)

Binding: entity=`TargetUserName`, value=`ServiceName`. Run across grains:

```
grain   cells   conformal floor 1/(n+1)   ENTROPY @α=1e-3     DISTINCT-COUNT thr=10 & thr=20
10m     42      0.023                      NONE                AR-WIN-2$   (both thresholds agree)
1h      36      0.027                      NONE                AR-WIN-2$
1d      10      0.091                      NONE                AR-WIN-2$
```

Refined probe (10m grain): conformal is **directionally correct but underpowered, not broken** — the
attacker's burst cell is *uniquely* the most extreme (p=0.047, H=3.60; every other cell p=1.0, H=0). A tuned
α≈0.05 would flag `AR-WIN-2$` and nothing else (separable). But the **standing α=1e-3 cannot be reached** —
the conformal floor 1/(n+1)=0.023 with only 42 cells sits ~20× above it. Distinct-count, encoding the human
prior "many distinct services = suspicious," flags the attacker **robustly** (thr=10 = thr=20), the *opposite*
of the synthetic brittleness.

## Why — it's the population, and it bounds the synthetic regime

This is exactly the corpus-dependence `fanout.py::detect_by_distinct_count` already documents: conformal earns
its distribution-free guarantee **on a large standing population** (faker's ~25k events / many benign cells),
and is underpowered **on a short pure-attack burst** (~10–42 cells), where the threshold's domain prior wins.
The synthetic and real captures sit on opposite ends of that axis:

- **faker-kerberos** = large population with benign background → conformal's upper-tail test has a
  well-populated null → threshold-robust detection. Synthetic finding valid **in this regime**.
- **splunk atomic-red-team** = isolated attack capture, no benign accounts → the conformal null is 2 noisy
  entities → floor >> any useful α → underpowered. Threshold wins.

So the real data does not refute the synthetic result; it **bounds its applicability**: *conformal-beats-
threshold holds on large standing populations, not on isolated attack captures.* That sharpening of the
applicability map is the canon-aligned value (the substrate + the map, not detector sophistication).

## What would actually close the caveat

Real telemetry with a **benign background population** — atomic-red-team isolated captures structurally cannot
provide it (they run the attack alone). Either (a) a real enterprise Kerberos capture with benign + attack
accounts, or (b) inject this real attack burst into a real benign 4769 population (semi-synthetic, weaker).
Until then the synthetic threshold-robustness result stays **regime-scoped to large standing populations** —
honest, not closed.

## One line

On real T1558.003 telemetry the fan-out battery's synthetic headline reverses — distinct-count robustly
catches the attacker while conformal entropy is underpowered (no benign population, 42 cells, floor 20× above
α) — which doesn't refute the synthetic result but bounds it to the large-standing-population regime; closing
the caveat needs real data with a benign background, which atomic-red-team captures don't have.
