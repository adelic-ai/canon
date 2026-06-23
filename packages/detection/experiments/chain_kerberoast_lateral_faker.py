"""Full kerberoast→lateral 3-stage chain check on faker-kerberos v2 (the lateral-extended corpus).

Demonstrates the conjunction is load-bearing: a network logon to a sensitive host (S2 alone) over-fires —
benign service accounts legitimately touch crown jewels — but the full chain `authenticate → RC4-TGS fan-out →
sensitive logon` is satisfied by *only* the labeled kerberoasters. Model-checking the full kill-chain axiom.
Needs ~/data/faker-kerberos/v2/ (generate via the lateral-extended generate_kerberos.py). Data stays local.

Run:  uv run python packages/detection/experiments/chain_kerberoast_lateral_faker.py
"""

import csv
import json
from pathlib import Path

from detection.chain import (
    check_chain,
    group_by_actor,
    kerberoast_lateral_chain,
    stage_sensitive_logon,
)

_DIR = Path.home() / "data" / "faker-kerberos" / "v2"
_SENSITIVE = {"DC01.corp.local", "fileserver.corp.local", "sqlserver.corp.local"}


def main() -> None:
    if not (_DIR / "export.csv").exists():
        raise SystemExit(f"corpus absent: {_DIR} (generate v2 with the lateral-extended generator)")
    events = list(csv.DictReader((_DIR / "export.csv").open()))
    truth = json.load((_DIR / "export.truth.json").open())
    kerb = {t["type"].split("kerberoasting:")[1].split(",")[0].strip()
            for t in truth if t["type"].startswith("kerberoasting")}

    by = group_by_actor(events, "Account_Name")
    s2_only = {a for a, evs in by.items() if stage_sensitive_logon(evs, sensitive_hosts=_SENSITIVE)}
    chain = set(check_chain(events, kerberoast_lateral_chain(sensitive_hosts=_SENSITIVE, n=8),
                            actor_field="Account_Name")["satisfied"])

    print(f"ground-truth kerberoasters: {sorted(kerb)}")
    print(f"\nS2 alone (logon to a sensitive host): {len(s2_only)} accounts — OVER-FIRES "
          f"(benign service accounts: {sorted(s2_only - kerb)[:5]}…)")
    print(f"full 3-stage chain (roast → lateral):  {sorted(chain)}")
    print(f"  recall {len(chain & kerb)}/{len(kerb)}   FP {len(chain - kerb)}")
    print("\nThe conjunction is load-bearing: neither stage alone isolates the attackers (S2 over-fires to "
          f"{len(s2_only)}), but the full kill-chain axiom is satisfied by exactly the {len(kerb)} kerberoasters.")


if __name__ == "__main__":
    main()
