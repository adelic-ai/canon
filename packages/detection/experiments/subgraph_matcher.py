"""Generalize the hand-coded lsass detection into a small subgraph-PATTERN MATCHER.

A detection is a subgraph pattern: one-or-more typed MOTIFS that must be present
and joined at a shared node. This module makes that declarative — you specify the
motifs (event-type + a field predicate + the join field) and the matcher finds the
joined instances over a corpus, then emits a justified verdict carrying the lineage
CID of every event it fired on.

It proves generalization two ways on the real OTRF LSASS_campaign_03 corpus:
  1. the two-motif lsass pattern (EID1 comsvcs ∧ EID10 lsass-VM_READ, joined at GUID)
     — reproduces the hand-coded result of lsass_subgraph_detection.py EXACTLY
     (same lineage CIDs, same decision), now from a declarative spec; and
  2. a single-motif pattern (EID10 lsass-VM_READ alone) — the broad SURFACER that
     catches every lsass reader (mostly benign), showing the matcher spans the
     scale ladder field → motif → multi-motif, and why the join sharpens precision.

Reuses cid()/load() from lsass_subgraph_detection so the CIDs are identical.

Run:  .venv/bin/python packages/detection/experiments/subgraph_matcher.py
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

import jsonschema

from lsass_subgraph_detection import PROCESS_VM_READ, SCHEMA, basename, cid, load


# --------------------------------------------------------------------------- #
# The pattern language — a motif is (event-type × field-predicate × join-field).
# Predicates are plain Python callables: no DSL, no framework, just a filter.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MotifSpec:
    role: str                       # label for this motif within the pattern
    eid: str                        # the EventID it matches
    join_field: str                 # the field holding the shared-node identity
    pred: Callable[[dict], bool]    # the content predicate over the raw event


@dataclass(frozen=True)
class PatternSpec:
    name: str
    technique: str
    motifs: tuple[MotifSpec, ...]   # 1 = single-motif surfacer; N = joined subgraph


def granted_has(e: dict, bit: int) -> bool:
    ga = e.get("GrantedAccess", "")
    return isinstance(ga, str) and ga.startswith("0x") and bool(int(ga, 16) & bit)


# --------------------------------------------------------------------------- #
# The matcher — find each motif's instances keyed by join value, then join on a
# shared value across ALL motifs (single-motif: every instance is a match).
# --------------------------------------------------------------------------- #
def _instances(events: list[dict], m: MotifSpec) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in events:
        if str(e.get("EventID")) == m.eid and m.pred(e):
            jv = e.get(m.join_field)
            if jv is not None:
                out.setdefault(jv, []).append(e)
    return out


def match_pattern(pattern: PatternSpec, events: list[dict]) -> list[dict]:
    """Return matches; each match maps role -> the raw event filling that motif."""
    per = [(m, _instances(events, m)) for m in pattern.motifs]
    if len(pattern.motifs) == 1:
        m, mp = per[0]
        return [{m.role: e} for insts in mp.values() for e in insts]
    shared = set.intersection(*[set(mp.keys()) for _, mp in per])  # the join
    matches = []
    for jv in sorted(shared):
        legs = [mp[jv] for _, mp in per]                            # instances per motif
        for combo in itertools.product(*legs):                     # usually 1×1
            matches.append({m.role: e for (m, _), e in zip(per, combo)})
    return matches


# --------------------------------------------------------------------------- #
# Verdict — generic grounding from whatever the match actually evidences.
# Lineage = the CID of every event in the match (drill-down walks back to these).
# --------------------------------------------------------------------------- #
def _temporal_ok(events: list[dict]) -> str:
    """∀-validate ordering across 2+ motifs; NONE if <2 or timestamps don't parse."""
    if len(events) < 2:
        return "none"
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    try:
        times = [datetime.strptime(e.get("UtcTime", ""), fmt) for e in events]
        return "true" if times == sorted(times) else "false"
    except (ValueError, TypeError):
        return "none"


def verdict_from_match(pattern: PatternSpec, match: dict, eid_collected: dict) -> tuple[dict, dict]:
    events = list(match.values())
    lineage = [cid(e) for e in events]
    subject = cid({"pattern": pattern.name, "lineage": lineage})
    any_user = any(e.get(f) for e in events for f in ("User", "SourceUser", "TargetUser"))
    any_host = any(e.get("Hostname") for e in events)
    verdict = {
        "technique": pattern.technique,
        "score": 1.0,                       # the pattern matched structurally
        "decision": "true",                 # all motifs present and joined
        "w_record": {
            "who": "true" if any_user else "none",
            "what": "true",                 # the motif predicate(s) matched the artifact
            "when": _temporal_ok(events),   # ordering validated only for multi-motif
            "where": "true" if any_host else "none",
            "how": "true",                  # the mechanism predicate matched
            "score": 1.0,
            "provenance": subject,
        },
        "guarantee": {"subject_cid": subject, "tier": "well-formed"},
        "custody": "none",                  # unsigned corpus
        "validity": {"verdict": "true", "deviation": []},
        "trustworthiness": "none",
        "provenance": subject,
    }
    manifest = {"pattern": pattern.name, "roles": {r: cid(e) for r, e in match.items()},
                "lineage": lineage}
    return verdict, manifest


# --------------------------------------------------------------------------- #
# Two patterns expressed in the same language — the whole point.
# --------------------------------------------------------------------------- #
LSASS_DUMP = PatternSpec(
    name="lsass_dump_via_comsvcs",
    technique="T1003.001",
    motifs=(
        MotifSpec("spawn", "1", "ProcessGuid",
                  lambda e: "comsvcs" in str(e.get("CommandLine", "")).lower()
                  and "minidump" in str(e.get("CommandLine", "")).lower()),
        MotifSpec("lsass_read", "10", "SourceProcessGUID",
                  lambda e: "lsass" in str(e.get("TargetImage", "")).lower()
                  and granted_has(e, PROCESS_VM_READ)),
    ),
)

LSASS_READ_ANY = PatternSpec(   # single-motif surfacer — the broad, lower-precision net
    name="lsass_vm_read_any",
    technique="T1003.001",
    motifs=(
        MotifSpec("lsass_read", "10", "SourceProcessGUID",
                  lambda e: "lsass" in str(e.get("TargetImage", "")).lower()
                  and granted_has(e, PROCESS_VM_READ)),
    ),
)


def main() -> None:
    events = load()
    eid_collected = {eid: any(str(e.get("EventID")) == eid for e in events) for eid in ("1", "10")}
    schema = json.loads(SCHEMA.read_text())

    # ---- 1. the two-motif pattern reproduces the hand-coded detection exactly ----
    m2 = match_pattern(LSASS_DUMP, events)
    print(f"[{LSASS_DUMP.name}]  matches: {len(m2)}  (the precise multi-motif detection)")
    assert len(m2) == 1, "expected exactly the comsvcs dump"
    v2, man2 = verdict_from_match(LSASS_DUMP, m2[0], eid_collected)
    jsonschema.validate(v2, schema)
    src = m2[0]
    print(f"    spawn      {basename(src['spawn']['Image'])}  {man2['roles']['spawn']}")
    print(f"    lsass_read GrantedAccess={src['lsass_read']['GrantedAccess']}  {man2['roles']['lsass_read']}")
    print(f"    join       ProcessGuid={src['spawn']['ProcessGuid']}")
    print(f"    verdict    decision={v2['decision']} when={v2['w_record']['when']} lineage={man2['lineage']}")

    # PROOF: same lineage CIDs as the hand-coded lsass_subgraph_detection.py
    EXPECTED = {"cid:sha256:9e876de1dafdd901", "cid:sha256:8960bc5559cfdee9"}
    assert set(man2["lineage"]) == EXPECTED, f"lineage drift: {man2['lineage']}"
    print("    ✓ reproduces the hand-coded verdict's lineage CIDs exactly\n")

    # ---- 2. the single-motif pattern: broad surfacer, spans the scale ladder ----
    m1 = match_pattern(LSASS_READ_ANY, events)
    total_lsass = sum(1 for e in events if str(e.get("EventID")) == "10"
                      and "lsass" in str(e.get("TargetImage", "")).lower())
    print(f"[{LSASS_READ_ANY.name}]  matches: {len(m1)}  (the broad single-motif surfacer)")
    readers = sorted({basename(e["lsass_read"].get("SourceImage", "")) for e in m1})
    print(f"    distinct VM_READ lsass readers it surfaces: {readers}")
    print(f"    → two levels of narrowing, both honest:")
    print(f"      • the VM_READ bit (mechanism predicate) already cuts {total_lsass} lsass accesses → {len(m1)}")
    print(f"        actual memory-readers (the query-only Vbox/svchost ones lack 0x10, correctly dropped)")
    print(f"      • the multi-motif JOIN (require the comsvcs spawn) cuts {len(m1)} → 1, pinning the")
    print(f"        comsvcs technique; winx64_payload / wmiprvse are different tools, correctly NOT matched.\n")

    print("One matcher; field/motif predicates + a join key express both a precise multi-motif")
    print("detection and a broad single-motif surfacer. Add a pattern = add a PatternSpec.")


if __name__ == "__main__":
    main()
