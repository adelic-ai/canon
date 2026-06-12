r"""W → technique routing: derive the technique from the observable, don't assert it.

The matcher cells hard-code `technique = "T1003.001"`. This closes the inversion's
core seam — given a flagged event's W-coordinates (here the data-component /
EventID), RETRIEVE the candidate techniques from the framework, so the technique
label is *derived*, not asserted.

The bridge the design notes worried about ("aligning canon-observable → framework
term is the hard open problem") is, in the NEWER ATT&CK schema, already encoded by
the framework: an `x-mitre-analytic` carries `x_mitre_log_source_references` with
`channel: "EventCode=10"` verbatim. So the routing chain is native:

    Sysmon event  →  channel "EventCode=10"  (the W 'how'/data-component)
      →  x-mitre-analytic (references that channel)
      →  x-mitre-detection-strategy (contains the analytic)
      →  detects →  attack-pattern (the technique)

Demonstrated on the real flagged lsass event from the matcher cells (Sysmon EID10):
routing derives T1003.001 among the candidates — WITHOUT the technique being given.
Two consequences fall out for free:
  - the detection-strategy's analytic lists ALL EIDs it wants {10,1,11,4673,13} —
    the framework saying "this is a multi-EID pattern" (validates the subgraph
    matcher) and which motifs to join;
  - we collected {1,10} but not {11,4673,13} → a computed COVERAGE gap (the
    completeness channel), derived from the framework, not guessed.

Run:  .venv/bin/python packages/detection/experiments/w_technique_routing.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

BUNDLE = Path(__file__).parents[3] / "packages/semantic-cyber/data/enterprise-attack.json"


def _attack_id(o: dict) -> str | None:
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def _eventcodes(channel: str) -> set[str]:
    """'EventCode=13, 14' -> {'13','14'}; non-EventCode channels -> empty."""
    if not channel or "eventcode" not in channel.lower():
        return set()
    return set(re.findall(r"\d+", channel))


def build_index(objs: list[dict]) -> dict:
    by_id = {o["id"]: o for o in objs}
    # analytic -> the set of Sysmon/Security EventCodes it references (+ data-component names)
    analytics = {}
    for o in objs:
        if o.get("type") != "x-mitre-analytic":
            continue
        codes, dcs = set(), set()
        for ls in o.get("x_mitre_log_source_references", []):
            codes |= _eventcodes(ls.get("channel", ""))
            dc = by_id.get(ls.get("x_mitre_data_component_ref", ""), {})
            if dc.get("name"):
                dcs.add(dc["name"])
        analytics[o["id"]] = {"codes": codes, "dcs": dcs}
    # detection-strategy -> (its analytics' union of codes/dcs)
    strat = {}
    for o in objs:
        if o.get("type") != "x-mitre-detection-strategy" or o.get("x_mitre_deprecated"):
            continue
        codes, dcs = set(), set()
        for an in o.get("x_mitre_analytic_refs", []):
            a = analytics.get(an, {})
            codes |= a.get("codes", set()); dcs |= a.get("dcs", set())
        strat[o["id"]] = {"name": o.get("name"), "codes": codes, "dcs": dcs}
    # detection-strategy --detects--> technique
    detects = {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects":
            detects.setdefault(o["source_ref"], []).append(o["target_ref"])
    return {"by_id": by_id, "strat": strat, "detects": detects}


def route_eventcode(idx: dict, code: str) -> list[dict]:
    """Observable (an EventCode) -> candidate techniques, via strategies whose
    analytics reference that code. Each candidate carries the strategy's full
    EID requirement (the multi-EID pattern + the coverage denominator)."""
    out = {}
    for sid, s in idx["strat"].items():
        if code not in s["codes"]:
            continue
        for tref in idx["detects"].get(sid, []):
            t = idx["by_id"].get(tref, {})
            tid = _attack_id(t)
            if tid and not t.get("x_mitre_deprecated"):
                out.setdefault(tid, {"name": t.get("name"), "strategy": s["name"],
                                     "wants_codes": s["codes"], "wants_dcs": s["dcs"]})
    return [{"technique": k, **v} for k, v in sorted(out.items())]


def main() -> None:
    objs = json.loads(BUNDLE.read_text())["objects"]
    idx = build_index(objs)

    # the flagged event from the matcher cells: Sysmon EID10 (the lsass VM_READ)
    OBSERVED = {"1", "10"}          # what canon collected in the cells
    candidates = route_eventcode(idx, "10")
    print(f"flagged observable: Sysmon EID10 (channel 'EventCode=10') — the W 'how'\n")
    print(f"W→technique routing (no technique given) → {len(candidates)} candidate techniques")
    print("  candidates include the hard-coded label?", any(c["technique"] == "T1003.001" for c in candidates))

    t = next(c for c in candidates if c["technique"] == "T1003.001")
    print(f"\nderived: {t['technique']} ({t['name']})  via strategy:")
    print(f"  \"{t['strategy']}\"")
    print(f"\nthe framework's own analytic for it is MULTI-EID — wants EventCodes: "
          f"{sorted(t['wants_codes'], key=int)}")
    print(f"  data-components: {sorted(t['wants_dcs'])}")
    have = sorted(OBSERVED & t["wants_codes"], key=int)
    miss = sorted(t["wants_codes"] - OBSERVED, key=int)
    print(f"\ncoverage (computed from the framework, not guessed):")
    print(f"  collected : {have}")
    print(f"  MISSING   : {miss}   → the completeness gap: collect these for full T1003.001 coverage")

    print(f"\nA few other candidates EID10 routes to (the observable is broad; the W's narrow it):")
    for c in candidates[:6]:
        if c["technique"] != "T1003.001":
            print(f"  {c['technique']:12} {c['name']}")

    print("\nThe technique was DERIVED from the observable via ATT&CK's native "
          "EventCode→analytic→strategy→technique chain — the inversion seam, closed.")


if __name__ == "__main__":
    main()
