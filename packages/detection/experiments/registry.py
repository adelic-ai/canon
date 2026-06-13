r"""P2 — make the cells callable: a Detector registry with observability-gated dispatch.

Turns the standalone cell scripts into a uniform, callable library so an
orchestrator (P3) can enumerate and fire them. Each Detector declares the
event-types it REQUIRES, so dispatch is gated on observability — a detector whose
required data-component isn't collected is SKIPPED (NONE-by-construction), not
run-and-falsely-cleared. This is the prereq for the orchestration search.

Light productization (canon hole #5): the *eventual* home is `src/detection/`;
this composes the experiment cells in place to unblock P3 without a full refactor.

Run:  .venv/bin/python packages/detection/experiments/registry.py
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from flow_orphan_patterns import DerivationRule, FlowPattern, OrphanPattern, match_flow, match_orphan
from lsass_subgraph_detection import cid, load
from subgraph_matcher import LSASS_DUMP, LSASS_READ_ANY, match_pattern


@dataclass(frozen=True)
class Finding:
    detector: str
    technique: str
    decision: str            # belnap: true / false / none / both
    lineage: tuple[str, ...] = ()   # CIDs back to the source events (drill-down)


@dataclass(frozen=True)
class Detector:
    name: str
    technique: str
    requires: frozenset[str]                 # EventIDs that must be present (observability gate)
    run: Callable[[list[dict]], list[Finding]]


# --- wrap the cells as uniform callables ----------------------------------- #
def _subgraph(spec, name) -> Callable[[list[dict]], list[Finding]]:
    def run(events: list[dict]) -> list[Finding]:
        return [Finding(name, spec.technique, "true",
                        tuple(cid(e) for e in m.values())) for m in match_pattern(spec, events)]
    return run


_GOLDEN = OrphanPattern(
    name="golden_ticket", technique="T1558.001", child=lambda e: True,
    rule=DerivationRule("4769", "4768", "TargetUserName", "TargetUserName", ordered=True),
)


def _orphan(events: list[dict]) -> list[Finding]:
    return [Finding("golden_ticket_orphan", "T1558.001", "true",
                    (cid(f["child"]),)) for f in match_orphan(_GOLDEN, events) if f["orphan"]]


_EXFIL = FlowPattern(
    name="exfil", source=lambda e: e.get("label") == "untrusted",
    sink=lambda e: e.get("tool") == "http.post" and "TOKEN=" in str(e.get("body", "")),
    rules=(DerivationRule("tool", "tool", "parent_node", "node"),),
)


def _flow(events: list[dict]) -> list[Finding]:
    return [Finding("exfil_taint_flow", "T1041", "true", tuple(f["path"]))
            for f in match_flow(_EXFIL, events)]


# --- Kerberos (faker-kerberos CSV format: EventCode + Ticket_Hash join) ----- #
# A Golden Ticket is BOTH milestones, split into two detectors so the orchestrator
# can chain them: forging the TGT = credential-access; using it across many services
# = lateral-movement (pass-the-ticket). Same evidence, two kill-chain steps.
from datetime import datetime  # noqa: E402

_KFMT = "%Y-%m-%d %H:%M:%S.%f"
TGT_LIFETIME_H = 10.0          # a mid-window orphan (first seen > a TGT lifetime in) can't be a pre-window TGT
FANOUT_MIN = 3                 # a forged ticket used across >=3 distinct services = lateral access


def _kerberos_forged(events: list[dict]) -> dict[str, list[dict]]:
    """Forged TGTs: 4769s whose Ticket_Hash has no issuing 4768 AND first seen mid-window
    (too late to be a benign pre-window TGT). Returns {ticket_hash: [4769 rows]}."""
    e4769 = [r for r in events if r.get("EventCode") == "4769"]
    times = [r["_time"] for r in events if r.get("_time")]
    if not e4769 or not times:
        return {}
    issued = {r["Ticket_Hash"] for r in events if r.get("EventCode") == "4768" and r.get("Ticket_Hash")}
    t0 = datetime.strptime(min(times), _KFMT)
    by_hash: dict[str, list[dict]] = {}
    for r in e4769:
        h = r.get("Ticket_Hash")
        if h and h not in issued:
            by_hash.setdefault(h, []).append(r)
    forged = {}
    for h, rs in by_hash.items():
        first = datetime.strptime(min(r["_time"] for r in rs), _KFMT)
        if (first - t0).total_seconds() / 3600 > TGT_LIFETIME_H:   # mid-window orphan = forged
            forged[h] = rs
    return forged


def _kerb_golden(events: list[dict]) -> list[Finding]:   # the FORGE = credential-access
    return [Finding("kerberos_golden_ticket", "T1558.001", "true", (cid({"ticket_hash": h}),))
            for h in _kerberos_forged(events)]


def _kerb_ptt(events: list[dict]) -> list[Finding]:      # the USE across services = lateral-movement
    out = []
    for h, rs in _kerberos_forged(events).items():
        services = {r["Service_Name"] for r in rs if r.get("Service_Name")}
        if len(services) >= FANOUT_MIN:
            out.append(Finding("kerberos_pass_the_ticket", "T1550.003", "true", (cid({"ticket_hash": h}),)))
    return out


# --- the registry ---------------------------------------------------------- #
REGISTRY: list[Detector] = [
    Detector("lsass_dump_subgraph", "T1003.001", frozenset({"1", "10"}), _subgraph(LSASS_DUMP, "lsass_dump_subgraph")),
    Detector("lsass_vm_read_surfacer", "T1003.001", frozenset({"10"}), _subgraph(LSASS_READ_ANY, "lsass_vm_read_surfacer")),
    Detector("golden_ticket_orphan", "T1558.001", frozenset({"4768", "4769"}), _orphan),
    Detector("exfil_taint_flow", "T1041", frozenset({"tool"}), _flow),
    Detector("kerberos_golden_ticket", "T1558.001", frozenset({"4769"}), _kerb_golden),
    Detector("kerberos_pass_the_ticket", "T1550.003", frozenset({"4769"}), _kerb_ptt),
]


def run_applicable(events: list[dict]) -> tuple[list[Finding], list[str]]:
    """Fire only detectors whose required event-types are present (observability gate).
    Returns (findings, skipped) — skipped = NONE-by-construction (not run, not cleared)."""
    present = {str(e.get("EventID")) for e in events} | {str(e.get("EventCode")) for e in events}
    present |= {"tool"} if any(e.get("EventID") == "tool" for e in events) else set()
    findings, skipped = [], []
    for d in REGISTRY:
        if d.requires <= present:
            findings.extend(d.run(events))
        else:
            skipped.append(f"{d.name} (needs {sorted(d.requires)}; missing {sorted(d.requires - present)})")
    return findings, skipped


def main() -> None:
    events = load()  # OTRF LSASS_campaign_03
    present = sorted({str(e.get("EventID")) for e in events})[:10]
    print(f"corpus: OTRF LSASS_campaign_03 ({len(events):,} events; EventIDs present incl. {present})\n")

    findings, skipped = run_applicable(events)
    print(f"=== detectors that FIRED (observability-gated dispatch) ===")
    for f in findings:
        print(f"  {f.detector:24} {f.technique:11} decision={f.decision}  lineage={list(f.lineage)}")
    print(f"\n=== detectors SKIPPED (required event-types not collected → NONE, not falsely-cleared) ===")
    for s in skipped:
        print(f"  {s}")
    print(f"\n{len(REGISTRY)} detectors registered; {len(findings)} findings; {len(skipped)} gated out.")
    print("The cells are now a uniform callable library with observability-gated dispatch — the prereq")
    print("for P3 (the orchestration search drives REGISTRY, guided by the kill-chain transition model).")


if __name__ == "__main__":
    main()
