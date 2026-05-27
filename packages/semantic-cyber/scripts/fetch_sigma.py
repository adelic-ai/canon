"""Fetch SigmaHQ rules into packages/semantic-cyber/data/sigma-rules/.

Downloads the master tarball of github.com/SigmaHQ/sigma (DRL 1.1
license) and extracts the six rule directories (rules, rules-compliance,
rules-dfir, rules-emerging-threats, rules-placeholder,
rules-threat-hunting). Other top-level directories (deprecated, tests,
documentation, etc.) are skipped.

Reproducible from the SigmaHQ repo; not checked into git. Re-run when a
SigmaHQ release pulls in interesting rule changes.
"""

from __future__ import annotations

import io
import sys
import tarfile
import urllib.request
from pathlib import Path


SIGMA_URL = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"

RULE_DIRS = {
    "rules",
    "rules-compliance",
    "rules-dfir",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
}


def main() -> int:
    here = Path(__file__).resolve().parent
    pkg = here.parent
    data = pkg / "data" / "sigma-rules"
    data.mkdir(parents=True, exist_ok=True)

    print(f"Fetching {SIGMA_URL}", flush=True)
    with urllib.request.urlopen(SIGMA_URL) as r:
        tar_bytes = r.read()
    print(f"Downloaded {len(tar_bytes):,} bytes; extracting", flush=True)

    count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile() or not member.name.endswith(".yml"):
                continue
            parts = Path(member.name).parts
            # Tarball layout: sigma-master/<top-dir>/<...>/<file>.yml
            if len(parts) < 3 or parts[1] not in RULE_DIRS:
                continue
            # Strip the leading "sigma-master/" component.
            target = data / Path(*parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src:
                target.write_bytes(src.read())
            count += 1

    print(f"Wrote {count:,} rules to {data}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
