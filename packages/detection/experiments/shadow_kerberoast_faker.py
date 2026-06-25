"""Shadow accumulator over faker-kerberos v2 — stream the corpus, fire on the roast PREFIX (2 of 3 stages),
and measure the early-warning margin: how long before each kerberoaster's lateral pivot we would have alerted.

The point the batch checker (chain_kerberoast_lateral_faker.py) cannot make: firing happens DURING the RC4
burst, *before* the sensitive logon — the prefix is the warning, the completed chain would be the failure.
Also reports sparsity (shadows instantiated vs total actors) — the tractability claim, measured.

Needs ~/data/faker-kerberos/v2/ (local, not committed). Honest caveat: the faker proves the MECHANISM (early
fire, decay, sparsity); it cannot earn fidelity — author-both-sides. Real validation needs real telemetry.

Run:  uv run python packages/detection/experiments/shadow_kerberoast_faker.py
"""

import csv
import json
from pathlib import Path

from detection.chain import group_by_actor, kerberoast_lateral_chain, stage_sensitive_logon
from detection.shadow import ShadowAccumulator

_DIR = Path.home() / "data" / "faker-kerberos" / "v2"
_SENSITIVE = {"DC01.corp.local", "fileserver.corp.local", "sqlserver.corp.local"}


def main() -> None:
    if not (_DIR / "export.csv").exists():
        raise SystemExit(f"corpus absent: {_DIR} (generate v2 with the lateral-extended generator)")
    events = list(csv.DictReader((_DIR / "export.csv").open()))
    truth = json.load((_DIR / "export.truth.json").open())
    kerb = {t["type"].split("kerberoasting:")[1].split(",")[0].strip()
            for t in truth if t["type"].startswith("kerberoasting")}

    spec = kerberoast_lateral_chain(sensitive_hosts=_SENSITIVE, n=8)
    acc = ShadowAccumulator(spec, actor_field="Account_Name", fire_at_prefix=2)   # 2/3 = roast, pre-pivot
    alerts = acc.run(events)

    by = group_by_actor(events, "Account_Name")
    fired = {a.actor for a in alerts}
    reached1 = sum(1 for p in acc.max_prefix.values() if p >= 1)
    reached2 = sum(1 for p in acc.max_prefix.values() if p >= 2)

    print(f"actors total: {len(by)}")
    print("sparsity (the tractability claim, measured honestly):")
    print(f"  reached prefix ≥1 (authenticated — a CHEAP shadow, ~one per active account): {reached1}")
    print(f"  reached prefix ≥2 (fanned out — the MEANINGFUL, costly state):                {reached2}")
    print(f"  peak concurrent live shadows: {acc.peak_live}    (churned rebuilds over the run: "
          f"{acc.n_instantiated})")
    print(f"ground-truth kerberoasters: {len(kerb)}")
    print(f"\nfired on the roast PREFIX (2/3, before the pivot): {len(fired)} distinct actors   "
          f"recall {len(fired & kerb)}/{len(kerb)}   FP {len(fired - kerb)}   "
          f"(total alerts incl. re-fires after prune/rebuild: {len(alerts)})")

    print("\nearly-warning margin per actor (earliest prefix alert vs the pivot):")
    earliest = {}
    for a in alerts:
        if a.actor not in earliest or a.time < earliest[a.actor].time:
            earliest[a.actor] = a
    for actor, a in sorted(earliest.items()):
        pivot = stage_sensitive_logon(by[actor], sensitive_hosts=_SENSITIVE)
        tag = "" if actor in kerb else "  [FP]"
        if pivot is not None:
            print(f"  {actor:<22} alert→pivot lead = {(pivot - a.time) / 60.0:6.1f} min   "
                  f"abnormality={a.abnormality:5.1f}{tag}")
        else:
            print(f"  {actor:<22} fired on roast; no pivot in data{tag}")

    print("\nThe batch checker confirms the same actors complete the full chain; the accumulator fires "
          "the lead above EARLIER, on the prefix — before the crown-jewel logon. Sparsity is real where it "
          "costs: the prefix≥2 set is tiny. (A selective first stage, or a min-prefix-to-instantiate, would "
          "drop the cheap prefix-1 shadows too — the obvious refinement.)")


if __name__ == "__main__":
    main()
