"""Detector registry — enumerate proper's detectors and dispatch by OBSERVABILITY.

The registry abstraction, promoted from experiments and *rebound to proper*: each entry wraps a
detector already in this package (its ``run`` returns canonical :class:`~forge_core.DetectionVerdict`,
not the experiment ``Finding``), and declares the corpus FIELDS it needs. :func:`run_applicable`
fires only detectors whose required fields are present — a detector whose data-component isn't
collected is SKIPPED (NONE-by-construction), never run-and-falsely-cleared. This is the single
"run every applicable detector over this corpus" entry point the orchestrator (and a Splunk sidecar)
plug into.

The gate is field-based and corpus-agnostic: a Kerberos CSV fires the Kerberos detectors and skips
the CloudTrail one (no ``userIdentity``/``awsRegion``); a CloudTrail log does the reverse.

Coverage grows as detectors promote. NOT yet registered (still experiment-only): the lsass-subgraph,
taint-flow/orphan, and enc-downgrade families. Coordination is also absent — it consumes host-activity
vectors, not a path-shaped corpus, so it needs a path adapter before it can join.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from forge_core import DetectionVerdict

from detection.cloudtrail import (
    CLOUDTRAIL_ENUMERATION,
    CLOUDTRAIL_REGION_SWEEP,
    load_cloudtrail_events,
    load_discovery_events,
)
from detection.cross_check import cross_check_verdicts, kerberoast_signature, ptt_signature
from detection.fanout import (
    PASSWORD_SPRAY,
    SERVICE_TICKET_FANOUT,
    fanout_verdicts,
    run_binding,
)
from detection.offhours import offhours_verdicts, run_offhours
from detection.rarity import cloud_account_manipulation_verdicts
from detection.subgraph import lsass_dump_verdicts


@dataclass(frozen=True)
class Detector:
    """A registry entry: a name + ATT&CK technique, the corpus fields it REQUIRES (observability gate),
    and a ``run`` that takes a corpus path and returns canonical verdicts."""

    name: str
    technique: str
    requires: frozenset[str]
    run: Callable[[str], list[DetectionVerdict]]


REGISTRY: list[Detector] = [
    Detector("password_spray", "T1110.003", frozenset({"Client_Address", "Account_Name"}),
             lambda p: fanout_verdicts(run_binding(p, PASSWORD_SPRAY))),
    Detector("service_ticket_fanout", "T1558.003", frozenset({"Account_Name", "Service_Name"}),
             lambda p: fanout_verdicts(run_binding(p, SERVICE_TICKET_FANOUT))),
    Detector("off_hours", "T1078", frozenset({"_time", "Account_Name"}),
             lambda p: offhours_verdicts(run_offhours(p))),
    Detector("kerberoasting", "T1558.003",
             frozenset({"Ticket_Encryption_Type", "Service_Name", "Account_Name"}),
             lambda p: cross_check_verdicts(p, binding=SERVICE_TICKET_FANOUT,
                                            signature=kerberoast_signature, technique="T1558.003")),
    Detector("pass_the_ticket", "T1550.003",
             frozenset({"Ticket_Hash", "Service_Name", "Account_Name"}),
             lambda p: cross_check_verdicts(p, binding=SERVICE_TICKET_FANOUT,
                                            signature=ptt_signature, technique="T1550.003")),
    Detector("cloudtrail_region_sweep", "T1496", frozenset({"userIdentity", "awsRegion"}),
             lambda p: fanout_verdicts(run_binding(p, CLOUDTRAIL_REGION_SWEEP, loader=load_cloudtrail_events))),
    Detector("cloudtrail_enumeration", "T1580", frozenset({"userIdentity", "eventName"}),
             lambda p: fanout_verdicts(run_binding(p, CLOUDTRAIL_ENUMERATION, loader=load_discovery_events))),
    Detector("cloud_account_manipulation", "T1098", frozenset({"userIdentity", "eventName"}),
             cloud_account_manipulation_verdicts),
    Detector("lsass_dump_subgraph", "T1003.001", frozenset({"EventID", "TargetImage", "GrantedAccess"}),
             lsass_dump_verdicts),
]


def corpus_fields(path: str) -> set[str]:
    """The field set available in a corpus — the observability surface the gate checks against.
    CSV → header columns; JSON → keys of the first record; JSONL (heterogeneous Sysmon) → the UNION of
    keys across ALL lines. The union is whole-file, not a prefix sample: in a Sysmon log the per-EventID
    fields a detector gates on (e.g. GrantedAccess on EID10) may first appear thousands of lines in, so a
    prefix sample would wrongly report the field absent and skip an applicable detector."""
    p = Path(path)
    if p.suffix == ".csv":
        with p.open(newline="") as f:
            return set(next(csv.reader(f)))
    text = p.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        fields: set[str] = set()
        for line in text.splitlines():              # JSONL — union keys across the whole file
            line = line.strip()
            if line:
                try:
                    fields |= set(json.loads(line).keys())
                except json.JSONDecodeError:
                    pass
        return fields
    recs = data if isinstance(data, list) else data.get("Records") or []
    return set(recs[0].keys()) if recs else set()


def run_applicable(path: str, *, fields: set[str] | None = None) -> tuple[list[DetectionVerdict], list[str]]:
    """Fire only detectors whose required fields are present in the corpus (observability gate).
    Returns ``(verdicts, skipped)`` — ``skipped`` entries are NONE-by-construction (the required
    data-component isn't collected), each with the missing fields named."""
    present = fields if fields is not None else corpus_fields(path)
    verdicts: list[DetectionVerdict] = []
    skipped: list[str] = []
    for d in REGISTRY:
        if d.requires <= present:
            verdicts.extend(d.run(path))
        else:
            skipped.append(f"{d.name} (needs {sorted(d.requires - present)})")
    return verdicts, skipped
