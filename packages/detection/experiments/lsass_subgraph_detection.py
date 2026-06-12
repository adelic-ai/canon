"""Worked example: a multi-EID detection as a SUBGRAPH PATTERN over the real
provenance graph, emitting a justified verdict that carries its INPUT LINEAGE.

Runs on the real OTRF LSASS_campaign_03 corpus (staged locally, 41,954 events).
This is the design developed in the web readouts, made concrete on real data:

  - an eventID is a typed MOTIF; the graph is interlocking motifs
    (web/process_provenance_graph.html)
  - a multi-EID detection is a SUBGRAPH PATTERN spanning motifs, joined at a
    shared content-addressed node — here EID1(comsvcs spawn) + EID10(lsass
    VM_READ) joined at the rundll32 ProcessGuid
  - the verdict carries its INPUT LINEAGE (the CID of every event it fired on),
    so drill-down is a walk back to the source node, not a fragile re-query
    (web/justified_verdict_substrate.html — the "fired on it but it's blank" case)
  - NONE vs FALSE is structural (web/completeness_channel.html): a missing EID10
    motif reads as NONE if EID10 is uncollected, FALSE-leaning if it is collected
    (here it IS — 30,074 EID10 events)

The emitted verdict conforms to contracts/detection_verdict.schema.json.

Run:  .venv/bin/python packages/detection/experiments/lsass_subgraph_detection.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import jsonschema

DATA = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
SCHEMA = Path(__file__).parents[3] / "contracts" / "detection_verdict.schema.json"

PROCESS_VM_READ = 0x10  # the bit you cannot dump lsass credentials without


def cid(obj: dict) -> str:
    """Content address of an event = its node id (one-hash-three-roles).

    sha256 over the canonical JSON bytes. Same event bytes -> same CID -> same
    node. This is the handle the verdict's lineage points back to: drill-down =
    re-resolve the CID over the corpus, not a re-query that might mismatch.
    """
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return "cid:sha256:" + hashlib.sha256(canonical).hexdigest()[:16]


def basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1] if path else ""


def load() -> list[dict]:
    return [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]


# --------------------------------------------------------------------------- #
# The two motifs, extracted as typed subgraphs keyed on the join node (GUID).
# --------------------------------------------------------------------------- #
def spawn_motif(events: list[dict]) -> dict | None:
    """EID1 motif: a process spawned as rundll32 running comsvcs MiniDump.
    The 'how' content-signature half (a known credential-dump LOLBin invocation)."""
    for e in events:
        if str(e.get("EventID")) == "1" and "comsvcs" in str(e.get("CommandLine", "")).lower() \
                and "minidump" in str(e.get("CommandLine", "")).lower():
            return {
                "cid": cid(e),
                "eid": "1",
                "guid": e.get("ProcessGuid"),
                "image": basename(e.get("Image", "")),
                "cmdline": e.get("CommandLine"),
                "user": e.get("User"),
                "host": e.get("Hostname"),
                "time": e.get("UtcTime"),
            }
    return None


def lsass_read_motif(events: list[dict], guid: str) -> dict | None:
    """EID10 motif: THIS process (same GUID) opens a VM_READ handle to lsass.
    The mechanism half — you cannot dump creds without GrantedAccess & 0x10."""
    for e in events:
        if str(e.get("EventID")) == "10" and e.get("SourceProcessGUID") == guid \
                and "lsass" in str(e.get("TargetImage", "")).lower():
            ga = e.get("GrantedAccess", "")
            ga_int = int(ga, 16) if isinstance(ga, str) and ga.startswith("0x") else 0
            return {
                "cid": cid(e),
                "eid": "10",
                "guid": e.get("SourceProcessGUID"),
                "target": basename(e.get("TargetImage", "")),
                "granted_access": ga,
                "vm_read": bool(ga_int & PROCESS_VM_READ),  # EXACT bit test, not endswith proxy
                "target_pid": e.get("TargetProcessId"),
                "user": e.get("SourceUser"),
                "host": e.get("Hostname"),
                "time": e.get("UtcTime"),
            }
    return None


def _belnap_temporal(spawn_t: str, read_t: str) -> str:
    """∀-validate the ordering: the spawn must precede the read. Earned-only when
    both timestamps parse and order holds; else NONE (never a faked true)."""
    try:
        fmt = "%Y-%m-%d %H:%M:%S.%f"
        return "true" if datetime.strptime(spawn_t, fmt) <= datetime.strptime(read_t, fmt) else "false"
    except (ValueError, TypeError):
        return "none"


def assemble_verdict(spawn: dict, read: dict | None, eid10_collected: bool) -> tuple[dict, dict]:
    """Emit a conforming DetectionVerdict + a lineage manifest. The verdict's
    decision is the kjoin of the two motif legs; a missing read leg is NONE (not
    FALSE) when EID10 is uncollected, FALSE-leaning when it is collected."""
    # the mechanism leg (did it read lsass with VM_READ?)
    if read is not None:
        read_leg = "true" if read["vm_read"] else "false"
    elif eid10_collected:
        # the motif is absent but the data component IS collected -> leans FALSE
        read_leg = "false"
    else:
        read_leg = "none"  # uncollected -> unobservable -> honest NONE, not a clean bill

    # ∃-detect (the spawn signature fired) ∧ the mechanism leg
    decision = "true" if (read_leg == "true") else read_leg

    when = _belnap_temporal(spawn["time"], read["time"]) if read else "none"
    lineage_cids = [spawn["cid"]] + ([read["cid"]] if read else [])
    subject = cid({"detection": "lsass_subgraph", "lineage": lineage_cids})

    verdict = {
        "technique": "T1003.001",
        "score": 1.0 if decision == "true" else 0.0,
        "decision": decision,
        "w_record": {
            "who": "true" if spawn.get("user") else "none",          # principal resolved
            "what": "true" if read else ("false" if eid10_collected else "none"),  # the lsass-Credential artifact touched
            "when": when,                                            # spawn precedes read (∀-validate)
            "where": "true" if spawn.get("host") else "none",        # host located
            "how": "true" if read and read["vm_read"] else "none",   # VM_READ mechanism matched
            "score": 1.0 if (read and read["vm_read"]) else 0.3,
            "provenance": subject,
        },
        "guarantee": {
            # mechanism+signature match on real data, but the JSON decode path is
            # unverified -> capped at well-formed (the source-tier discipline).
            "subject_cid": subject,
            "tier": "well-formed",
        },
        "custody": "none",       # corpus is unsigned NDJSON -> can't vouch for the chain
        "validity": {"verdict": "true", "deviation": []},  # events parsed + conform to expected kind
        "trustworthiness": "none",  # kjoin(custody=none, validity-as-integrity=none) = none
        "provenance": subject,
    }
    manifest = {
        "pattern": "EID1(comsvcs spawn) ∧ EID10(rundll32 → lsass VM_READ), joined at ProcessGuid",
        "join_key": spawn["guid"],
        "motifs": {"spawn": spawn, "lsass_read": read},
        "lineage_cids": lineage_cids,
        "read_leg": read_leg,
        "eid10_collected": eid10_collected,
    }
    return verdict, manifest


def main() -> None:
    events = load()
    eid10_collected = any(str(e.get("EventID")) == "10" for e in events)
    by_cid = {cid(e): e for e in events}  # the "drill-down" index: CID -> source event

    spawn = spawn_motif(events)
    assert spawn is not None, "expected the comsvcs MiniDump spawn in this corpus"
    read = lsass_read_motif(events, spawn["guid"])

    verdict, manifest = assemble_verdict(spawn, read, eid10_collected)
    jsonschema.validate(verdict, json.loads(SCHEMA.read_text()))  # conforms to the PINNED contract

    print(f"corpus: {len(events):,} events  |  EID10 collected: {eid10_collected}  ({sum(1 for e in events if str(e.get('EventID'))=='10'):,} events)\n")
    print("=== the subgraph pattern (two motifs, joined at one node) ===")
    print(f"  motif A  EID1   {spawn['image']} :: {spawn['cmdline'][:60]}")
    print(f"                  {spawn['cid']}")
    print(f"  motif B  EID10  -> {read['target']}  GrantedAccess={read['granted_access']}  VM_READ={read['vm_read']}")
    print(f"                  {read['cid']}")
    print(f"  join     ProcessGuid={manifest['join_key']}  (same node in both motifs)\n")

    print("=== the justified verdict (conforms to detection_verdict.schema.json) ===")
    print(f"  technique      {verdict['technique']}   decision={verdict['decision']}  score={verdict['score']}")
    print(f"  w_record       who={verdict['w_record']['who']} what={verdict['w_record']['what']} "
          f"when={verdict['w_record']['when']} where={verdict['w_record']['where']} how={verdict['w_record']['how']}")
    print(f"  guarantee      tier={verdict['guarantee']['tier']}   custody={verdict['custody']}   trust={verdict['trustworthiness']}")
    print(f"  provenance     {verdict['provenance']}\n")

    print("=== drill-down = walk the lineage CIDs back to the source events ===")
    for c in manifest["lineage_cids"]:
        src = by_cid[c]
        print(f"  {c}  ->  EID{src.get('EventID')}  resolved: PID {src.get('ProcessId', src.get('SourceProcessId'))} on {src.get('Hostname')}")
    print("  (present -> the data is right here; absent -> a gap with a recorded reason, not a mystery)\n")

    print("=== the honest NONE contrast (the structural NONE-vs-FALSE) ===")
    v_nocollect, _ = assemble_verdict(spawn, None, eid10_collected=False)
    v_collected, _ = assemble_verdict(spawn, None, eid10_collected=True)
    print(f"  spawn present, EID10 motif absent & EID10 UNCOLLECTED -> decision={v_nocollect['decision']}  "
          f"(unobservable; NOT a clean bill)")
    print(f"  spawn present, EID10 motif absent & EID10 COLLECTED   -> decision={v_collected['decision']}  "
          f"(we watch it, it didn't fire -> leans the read didn't happen)")
    print(f"  here EID10 IS collected AND the motif IS present       -> decision={verdict['decision']}  "
          f"(the read is grounded)")


if __name__ == "__main__":
    main()
