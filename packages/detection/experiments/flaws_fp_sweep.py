r"""FP sweep — corpus-wide false-positive rate for the cloud detectors over ALL of flaws.cloud.

Earlier validation ran on file 00 (100k events). This runs the three cloud detectors over the FULL
corpus (20 files, ~1.9M events — the 19 .json.gz now readable via the gz-aware loader), accumulating
each detector's population across all files (one conformal population, not per-file), then classifies
every flagged entity. The question the per-file result couldn't answer: do the detectors stay selective
at 20x the data, or do false positives (the benign security scanners, root) accumulate?

Ground truth is SCENARIO-BASED (flaws has no per-event label file):
  MALICIOUS = attacker credentials — `backup` (cryptojacking), `Level6` (recon), `i-*` (stolen EC2
              instance roles doing IAM).
  BENIGN    = `secmonkey`/`SecurityMokey`/`cloudaux`/`cloudsploit_scan` (security scanners), `AWSService`,
              `root` (the account owner).
Entities in neither bucket are reported as `?` (unclassified) — not forced, so the precision number
isn't inflated by a convenient label.

Run:  .venv/bin/python packages/detection/experiments/flaws_fp_sweep.py
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
from collections import Counter
from pathlib import Path

from detection.cloudtrail import (
    CLOUDTRAIL_ENUMERATION,
    CLOUDTRAIL_REGION_SWEEP,
    DISCOVERY_APIS,
    MANIPULATION_APIS,
    _identity,
)
from detection.fanout import detect_fanout
from detection.rarity import rare_actors

CORPUS = Path.home() / "data/flaws-cloudtrail/v1"
_EPOCH = dt.datetime(1970, 1, 1)
MALICIOUS = {"backup", "Level6"}
BENIGN = {"secmonkey", "SecurityMokey", "cloudaux", "cloudsploit_scan", "AWSService",
          "root", "arn:aws:iam::811596193553:root"}


def _records(f: Path) -> list[dict]:
    opener = gzip.open if str(f).endswith(".gz") else open
    with opener(f, "rt") as fh:
        return json.load(fh)["Records"]


def _t(e: dict) -> float:
    return (dt.datetime.strptime(e["eventTime"], "%Y-%m-%dT%H:%M:%SZ") - _EPOCH).total_seconds()


def _label(e: str) -> str:
    if e in MALICIOUS or e.startswith("i-"):
        return "TP"
    if e in BENIGN:
        return "FP"
    return "?"


def _score(name: str, flagged: set[str]) -> None:
    tp = sorted(e for e in flagged if _label(e) == "TP")
    fp = sorted(e for e in flagged if _label(e) == "FP")
    unc = sorted(e for e in flagged if _label(e) == "?")
    prec = len(tp) / (len(tp) + len(fp)) if (tp or fp) else float("nan")
    print(f"  {name:22} flagged={len(flagged):2}  TP={len(tp)} FP={len(fp)} ?={len(unc)}  precision={prec:.0%}")
    print(f"      TP {tp}")
    if fp:
        print(f"      FP {fp}   <-- FALSE POSITIVES")
    if unc:
        print(f"      ?  {unc}")


def main() -> None:
    files = sorted(CORPUS.glob("flaws_cloudtrail*.json*"))
    region: list = []
    discovery: list = []
    manip: Counter = Counter()
    total = 0
    for f in files:
        recs = _records(f)
        total += len(recs)
        for e in recs:
            t, who, en = _t(e), _identity(e), e.get("eventName")
            region.append((t, who, e.get("awsRegion", "-")))
            if en in DISCOVERY_APIS:
                discovery.append((t, who, en))
            if en in MANIPULATION_APIS:
                manip[who] += 1
    print(f"FP sweep: {len(files)} files, {total:,} events "
          f"({len(region):,} region / {len(discovery):,} discovery / {sum(manip.values()):,} manip)\n")

    rs = {d.cell.entity for d in detect_fanout(
        region, grain_seconds=CLOUDTRAIL_REGION_SWEEP.grain_seconds, alpha=CLOUDTRAIL_REGION_SWEEP.alpha)["detected"]}
    en = {d.cell.entity for d in detect_fanout(
        discovery, grain_seconds=CLOUDTRAIL_ENUMERATION.grain_seconds, alpha=CLOUDTRAIL_ENUMERATION.alpha)["detected"]}
    am = {e for e, _, _ in rare_actors(manip, max_share=0.05)}

    print("per-detector, corpus-wide (one population over all 20 files):")
    _score("region_sweep T1496", rs)
    _score("enumeration  T1580", en)
    _score("account_manip T1098", am)
    print("\nGround truth is scenario-based (flaws has no event-label file); '?' = unclassified, not forced.")


if __name__ == "__main__":
    main()
