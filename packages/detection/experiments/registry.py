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


# --- the registry ---------------------------------------------------------- #
REGISTRY: list[Detector] = [
    Detector("lsass_dump_subgraph", "T1003.001", frozenset({"1", "10"}), _subgraph(LSASS_DUMP, "lsass_dump_subgraph")),
    Detector("lsass_vm_read_surfacer", "T1003.001", frozenset({"10"}), _subgraph(LSASS_READ_ANY, "lsass_vm_read_surfacer")),
    Detector("golden_ticket_orphan", "T1558.001", frozenset({"4768", "4769"}), _orphan),
    Detector("exfil_taint_flow", "T1041", frozenset({"tool"}), _flow),
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
