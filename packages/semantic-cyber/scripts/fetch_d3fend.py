"""Fetch d3fend.ttl from MITRE into packages/semantic-cyber/data/.

D3FEND.ttl is large (~3.4MB) and reproducible; not checked into git.
Re-run when MITRE publishes ontology updates.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path


D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.ttl"


def main() -> int:
    here = Path(__file__).resolve().parent
    pkg = here.parent
    data = pkg / "data"
    data.mkdir(exist_ok=True)
    target = data / "d3fend.ttl"

    print(f"Fetching {D3FEND_URL} → {target}", flush=True)
    with urllib.request.urlopen(D3FEND_URL) as r:
        target.write_bytes(r.read())

    print(f"Wrote {target.stat().st_size:,} bytes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
