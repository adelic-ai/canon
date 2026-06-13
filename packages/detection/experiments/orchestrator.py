r"""P3 — the orchestration search: drive the detector registry (P2), guided by the
kill-chain transition model (P1).

This is the engine that turns a list of cells into a system. It does NOT fire every
detector blindly; it sequences them by the kill-chain:

  1. Fire the applicable detectors (observability-gated) → findings.
  2. Map each finding to its ATT&CK tactic — the attack-path-so-far.
  3. For each confirmed tactic, consult the LEARNED transition model: what milestone
     most likely comes next? (forward-progression — the data-backed prior.)
  4. Classify each expected-next milestone:
       COVERED            — a detector exists AND its data is collected → fire it next.
       OBSERVABILITY-GAP  — a detector exists but its required data isn't collected.
       COVERAGE-GAP       — no detector exists for that milestone at all.

The expected-next list, sorted by transition probability, IS the best-first search
frontier — where to point the next detector. The gaps are the reachable-NONE frontier:
the moves we have data-backed reason to expect but cannot yet verify. The orchestrator
asserts nothing it can't ground — a gap is reported as a gap, not a clean bill.

Run:  .venv/bin/python packages/detection/experiments/orchestrator.py
"""

from __future__ import annotations

import collections

from killchain_transitions import build_model, forward_nexts
from lsass_subgraph_detection import load
from registry import REGISTRY, run_applicable

# technique → ATT&CK tactic, for the registered detectors (the kill-chain milestone each confirms)
TECH_TACTIC = {
    "T1003.001": "credential-access",   # OS Credential Dumping: LSASS Memory
    "T1558.001": "credential-access",   # Steal or Forge Kerberos Tickets: Golden Ticket
    "T1041": "exfiltration",            # Exfiltration Over C2 Channel
}


def _present(events: list[dict]) -> set[str]:
    p = {str(e.get("EventID")) for e in events} | {str(e.get("EventCode")) for e in events}
    return p | ({"tool"} if any(e.get("EventID") == "tool" for e in events) else set())


def orchestrate(events: list[dict]):
    """Returns (observed_tactics, frontier, skipped). frontier = the forward search frontier:
    (from_tactic, next_tactic, prob, status, detail), sorted by prob within each from_tactic."""
    nexts = forward_nexts(build_model()[0])
    findings, skipped = run_applicable(events)
    present = _present(events)

    by_tactic: dict[str, list] = collections.defaultdict(list)
    for d in REGISTRY:
        by_tactic[TECH_TACTIC.get(d.technique, "?")].append(d)

    observed: list[str] = []
    for f in findings:
        t = TECH_TACTIC.get(f.technique, "?")
        if t not in observed:
            observed.append(t)

    frontier = []
    for t in observed:
        for nt, p in nexts.get(t, [])[:4]:        # top expected-next milestones
            dets = by_tactic.get(nt, [])
            if not dets:
                status, detail = "COVERAGE-GAP", "no detector registered for this milestone"
            elif any(d.requires <= present for d in dets):
                fire = [d.name for d in dets if d.requires <= present]
                status, detail = "COVERED", f"fire next: {fire}"
            else:
                status, detail = "OBSERVABILITY-GAP", f"detector exists {[d.name for d in dets]} but data not collected"
            frontier.append((t, nt, p, status, detail))
    return observed, findings, frontier, skipped


def main() -> None:
    events = load()  # OTRF LSASS_campaign_03
    observed, findings, frontier, skipped = orchestrate(events)

    print(f"corpus: OTRF LSASS_campaign_03 ({len(events):,} events)\n")
    print("=== STEP 1-2 — fired detectors → attack-path-so-far (confirmed milestones) ===")
    for f in findings:
        print(f"  {f.detector:24} {f.technique:11} → {TECH_TACTIC.get(f.technique,'?')}")
    print(f"  confirmed milestones: {observed or '(none)'}")

    print("\n=== STEP 3-4 — forward search frontier (transition model → where to look next) ===")
    for t, nt, p, status, detail in frontier:
        flag = {"COVERED": "→", "OBSERVABILITY-GAP": "▲", "COVERAGE-GAP": "✗"}[status]
        print(f"  {flag} {t} → {nt:18} p={p:.0%}  [{status}] {detail}")

    print("\n=== reachable-NONE frontier — expected next moves we CANNOT yet verify ===")
    gaps = [(nt, p, status) for _, nt, p, status, _ in frontier if status != "COVERED"]
    for nt, p, status in sorted(set(gaps), key=lambda x: -x[1]):
        print(f"  {nt:18} p={p:.0%}  ({status})")

    print("\nThe engine: fire → map to milestone → consult the LEARNED transition model → point the next")
    print("detector at the highest-probability next move. On OTRF the credential-access dump is confirmed;")
    print("the model says lateral-movement is the most likely next step (43%) — and the orchestrator reports")
    print("HONESTLY that no detector covers it here (a coverage gap), rather than implying the host is clean.")


if __name__ == "__main__":
    main()
