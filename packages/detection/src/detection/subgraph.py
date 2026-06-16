"""Subgraph-pattern detection — the structural paradigm for multi-EID telemetry.

A detection as a SUBGRAPH PATTERN: one-or-more typed MOTIFS (an EventID + a content predicate + a join
field) that must be present and joined at a shared node. Deterministic and lineage-carrying — the
structural complement to the statistical fan-out. Promoted from experiments; emits canonical
:class:`~forge_core.DetectionVerdict`s via :func:`~detection._verdict.emit_detection_verdict`. A
structural exact-match has no calibrated FAR, so the verdict carries ``calibration=None`` (like rarity
/ cross_check); the temporal ordering is the ``when`` ∀-validate fold, earned only for multi-motif.

First patterns — ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory), validated on OTRF
LSASS_campaign_03:
  ``LSASS_DUMP``     — two-motif subgraph: EID1 comsvcs+minidump spawn ∧ EID10 lsass VM_READ, joined at
                      the process GUID. Precise (the comsvcs dump).
  ``LSASS_READ_ANY`` — single-motif surfacer: any EID10 lsass VM_READ. Broad, lower precision.
"""

from __future__ import annotations

import datetime as dt
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from forge_core import DetectionVerdict
from provenance import NONE, TRUE, Four

from detection._verdict import emit_detection_verdict

PROCESS_VM_READ = 0x10  # the GrantedAccess bit you cannot dump lsass credentials without


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


def _instances(events: list[dict], m: MotifSpec) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in events:
        if str(e.get("EventID")) == m.eid and m.pred(e):
            jv = e.get(m.join_field)
            if jv is not None:
                out.setdefault(jv, []).append(e)
    return out


def match_pattern(pattern: PatternSpec, events: list[dict]) -> list[dict]:
    """Each match maps ``role -> the raw event filling that motif``; multi-motif matches are joined
    on the shared node identity."""
    per = [(m, _instances(events, m)) for m in pattern.motifs]
    if len(pattern.motifs) == 1:
        m, mp = per[0]
        return [{m.role: e} for insts in mp.values() for e in insts]
    shared = set.intersection(*[set(mp.keys()) for _, mp in per])   # the join
    matches = []
    for jv in sorted(shared):
        legs = [mp[jv] for _, mp in per]
        for combo in itertools.product(*legs):
            matches.append({m.role: e for (m, _), e in zip(per, combo)})
    return matches


LSASS_DUMP = PatternSpec("lsass_dump_via_comsvcs", "T1003.001", (
    MotifSpec("spawn", "1", "ProcessGuid",
              lambda e: "comsvcs" in str(e.get("CommandLine", "")).lower()
              and "minidump" in str(e.get("CommandLine", "")).lower()),
    MotifSpec("lsass_read", "10", "SourceProcessGUID",
              lambda e: "lsass" in str(e.get("TargetImage", "")).lower()
              and granted_has(e, PROCESS_VM_READ)),
))
LSASS_READ_ANY = PatternSpec("lsass_vm_read_any", "T1003.001", (
    MotifSpec("lsass_read", "10", "SourceProcessGUID",
              lambda e: "lsass" in str(e.get("TargetImage", "")).lower()
              and granted_has(e, PROCESS_VM_READ)),
))


def load_sysmon_events(path: str) -> list[dict]:
    """Sysmon JSONL (one event per line) → list of event dicts."""
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def _temporal_ok(events: list[dict]) -> Four:
    """The ``when`` ∀-validate fold: are the joined events in causal order? NONE for <2 (nothing to
    order) or unparseable timestamps."""
    if len(events) < 2:
        return NONE
    try:
        times = [dt.datetime.strptime(e.get("UtcTime", ""), "%Y-%m-%d %H:%M:%S.%f") for e in events]
    except (ValueError, TypeError):
        return NONE
    return TRUE if times == sorted(times) else NONE


def pattern_verdicts(
    pattern: PatternSpec,
    events: list[dict],
    *,
    corroborate: Callable[[dict], dict | None] | None = None,
) -> list[DetectionVerdict]:
    """Run a subgraph ``pattern`` over ``events`` → canonical verdicts. Structural exact match ⇒ no
    calibrated FAR (``calibration=None``); ``what``/``how`` TRUE (the predicate matched the artifact/
    mechanism); ``who``/``where`` grounded from the events; ``when`` from the temporal fold.

    ``corroborate`` is an optional dependency-injected external witness: given a match (``role -> event``),
    it returns a corroboration dict (``{rules, votes, ...}``) or ``None``. The corroboration is recorded as
    a PROVENANCE EDGE on the verdict's root (not on ``cross_check``) — see
    :func:`detection._verdict.build_detection_root`. This keeps the structural module ignorant of *who*
    corroborates (the Sigma panel is wired in by :mod:`detection.cross_check`, not imported here)."""
    out = []
    for match in match_pattern(pattern, events):
        evs = list(match.values())
        who = TRUE if any(e.get(f) for e in evs for f in ("User", "SourceUser", "TargetUser")) else NONE
        where = TRUE if any(e.get("Hostname") for e in evs) else NONE
        join = evs[0].get(pattern.motifs[0].join_field, "?")
        corro = corroborate(match) if corroborate is not None else None
        out.append(emit_detection_verdict(
            f"{pattern.name}|{join}",
            technique=pattern.technique,
            pvalue=1e-6,                      # nominal structural-precision proxy — NOT a calibrated FAR (calibration None)
            params={"pattern": pattern.name, "roles": list(match)},
            what=TRUE, how=TRUE, who=who, where=where, when=_temporal_ok(evs),
            calibration=None, corroboration=corro,
        ))
    return out


def lsass_dump_verdicts(path: str) -> list[DetectionVerdict]:
    """The precise comsvcs LSASS-dump subgraph over a Sysmon JSONL corpus → T1003.001 verdicts."""
    return pattern_verdicts(LSASS_DUMP, load_sysmon_events(path))
