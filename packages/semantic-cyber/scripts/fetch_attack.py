"""Fetch enterprise-attack.json from MITRE into packages/semantic-cyber/data/.

The bundle is ~51MB and reproducible from MITRE's attack-stix-data repo;
not checked into git. Re-run when MITRE publishes a new ATT&CK release.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path


ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def main() -> int:
    here = Path(__file__).resolve().parent
    pkg = here.parent
    data = pkg / "data"
    data.mkdir(exist_ok=True)
    target = data / "enterprise-attack.json"

    print(f"Fetching {ATTACK_URL} → {target}", flush=True)
    with urllib.request.urlopen(ATTACK_URL) as r:
        target.write_bytes(r.read())

    print(f"Wrote {target.stat().st_size:,} bytes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
