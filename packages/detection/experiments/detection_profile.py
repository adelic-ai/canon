r"""The toggle — turn concerns/detectors OFF per deployment, where OFF ≠ NONE.

A customer with unsigned logs shouldn't see a custody axis on every verdict that is permanently
`none`; a customer with no HR/shift baseline shouldn't run off-hours at all. Both are "turn it
off." But OFF is NOT a value of the four-valued carrier (None/True/False/Both) — it's a
DEPLOYMENT-CONFIG fact, recorded at the envelope level:

  NONE  = the axis was evaluated and found no basis        (custody = "none": unsigned feed seen)
  OFF   = the axis is not evaluated in this deployment      (axis absent + listed in profile.disabled_axes)

Two toggle levels, both governed by a Profile:
  * detector toggle  — which detectors run at all (off-hours is parked: default OFF, enable-able).
  * concern toggle   — which axes the verdict envelope carries (custody/trustworthiness OFF on
                       unsigned-log deployments). A disabled axis is DROPPED, and the schema is
                       adjusted to not require it — so the reduced verdict still validates.

This prototypes what #5 promotes into contracts/forge-core; it does not mutate the committed
REGISTRY or the base schema.

Run:  .venv/bin/python packages/detection/experiments/detection_profile.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import jsonschema

from kerberos_behavior_detectors import off_hours
from lsass_subgraph_detection import load as load_otrf
from registry import REGISTRY, Detector, Finding, cid
from subgraph_matcher import LSASS_DUMP, match_pattern, verdict_from_match

SCHEMA = Path(__file__).parents[3] / "contracts/detection_verdict.schema.json"

# off-hours as a TOGGLEABLE detector — parked (default OFF), not hardcoded out. Available to enable.
OFFHOURS = Detector("off_hours", "T1078", frozenset({"4769"}),
                    lambda ev: [Finding("off_hours", "T1078", "true", (cid({"account": a}),)) for a in off_hours(ev)])
ALL_DETECTORS = REGISTRY + [OFFHOURS]

CORE_AXES = frozenset({"technique", "score", "decision", "w_record", "guarantee", "validity", "provenance"})
CUSTODY_AXES = frozenset({"custody", "trustworthiness", "custody_localization"})


@dataclass(frozen=True)
class Profile:
    name: str
    detectors: frozenset    # enabled detector names
    concerns: frozenset     # enabled verdict axes


FULL = Profile("full", frozenset(d.name for d in ALL_DETECTORS), CORE_AXES | CUSTODY_AXES)
# the common real deployment: unsigned logs (no custody chain) + no HR baseline (no off-hours)
TELEMETRY_ONLY = Profile("telemetry-only", frozenset(d.name for d in REGISTRY), CORE_AXES)


def detectors_for(p: Profile) -> list[Detector]:
    return [d for d in ALL_DETECTORS if d.name in p.detectors]


def apply_profile(verdict: dict, p: Profile) -> dict:
    """Drop disabled axes; record the OFF state explicitly (≠ NONE)."""
    kept = {k: v for k, v in verdict.items() if k in p.concerns}
    kept["profile"] = {"name": p.name, "disabled_axes": sorted(set(verdict) - p.concerns)}
    return kept


def schema_for(p: Profile) -> dict:
    """Base schema with disabled axes removed from `required` — so a reduced verdict validates."""
    s = json.loads(SCHEMA.read_text())
    s["required"] = [r for r in s.get("required", []) if r in p.concerns]
    return s


def main() -> None:
    # a real verdict to toggle over (the OTRF comsvcs lsass dump)
    events = load_otrf()
    match = match_pattern(LSASS_DUMP, events)[0]
    verdict, _ = verdict_from_match(LSASS_DUMP, match, {"1": True, "10": True})

    print("=== CONCERN toggle on a real verdict (custody axis) — OFF vs NONE ===")
    for p in (FULL, TELEMETRY_ONLY):
        v = apply_profile(verdict, p)
        jsonschema.validate(v, schema_for(p))                 # reduced verdict still validates
        custody = v.get("custody", "<<absent>>")
        print(f"  [{p.name:14}] custody={custody!r:12} disabled_axes={v['profile']['disabled_axes']}  (schema: OK)")
    print("  FULL: custody='none' = evaluated, unsigned feed seen.  TELEMETRY_ONLY: custody ABSENT =")
    print("  not evaluated by config (in disabled_axes). Same carrier (4-valued) — OFF lives in the profile.\n")

    print("=== DETECTOR toggle (off-hours: parked = default OFF, enable-able) ===")
    for p in (TELEMETRY_ONLY, FULL):
        names = [d.name for d in detectors_for(p)]
        has_oh = "off_hours" in names
        print(f"  [{p.name:14}] {len(names)} detectors; off_hours {'ON' if has_oh else 'OFF (not run)'}")
    fired = off_hours(__import__('kerberos_orphan_real').load())
    print(f"  enabling off_hours adds a detector that fires on {len(fired)} faker accounts at ~5% precision —")
    print(f"  the customer chooses to bear that. OFF = absent from the suite, NOT 'ran and found nothing'.")


if __name__ == "__main__":
    main()
