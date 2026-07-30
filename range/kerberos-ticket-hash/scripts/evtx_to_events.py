#!/usr/bin/env python3
"""Feed the real captured events into the existing detector.

Reads the JSONL that 06-export-and-verify.ps1 produces (one flattened Security
event per line), maps the raw Windows EventData field names onto the keys
detection.kerberos_tickets expects, and runs the real detector.

Real 4768/4769 already use ``IpAddress`` and ``TargetUserName`` verbatim — those
pass through. The ONLY unknowns are the two ticket-hash fields, whose real
``<Data Name=...>`` names 06 prints. Put the confirmed names in FIELD_MAP below
(one place) — that same correction then belongs in kerberos_tickets.py.

Usage:  python evtx_to_events.py dc01-events.jsonl [mbr01-events.jsonl ...]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# --- import the real detector (works inside the uv workspace venv, or falls
#     back to the source tree) ------------------------------------------------
try:
    from detection.kerberos_tickets import (
        REQUEST_TICKET_HASH,
        RESPONSE_TICKET_HASH,
        detect_ticket_attacks,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "packages/detection/src"))
    from detection.kerberos_tickets import (  # noqa: E402
        REQUEST_TICKET_HASH,
        RESPONSE_TICKET_HASH,
        detect_ticket_attacks,
    )

# ── CONFIRM THESE against 06's "distinct <Data Name=...>" output, then set the
#    same two names in detection/kerberos_tickets.py. Left = raw Windows name,
#    right = the canonical key the detector reads. If the real names already ARE
#    RequestTicketHash / ResponseTicketHash, this map is a no-op and the guess
#    was right. ─────────────────────────────────────────────────────────────
FIELD_MAP = {
    # "TicketHashRequested":  REQUEST_TICKET_HASH,
    # "TicketHashResponse":   RESPONSE_TICKET_HASH,
}


def load(paths: list[str]) -> list[dict]:
    events: list[dict] = []
    for p in paths:
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            for raw, canonical in FIELD_MAP.items():
                if raw in e:
                    e[canonical] = e.pop(raw)
            events.append(e)
    return events


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    events = load(argv)
    hashed = sum(1 for e in events if e.get(REQUEST_TICKET_HASH) or e.get(RESPONSE_TICKET_HASH))
    print(f"loaded {len(events)} events; {hashed} carry a ticket-hash field "
          f"({'HASH tier' if hashed else 'METADATA tier — no hashes seen, check FIELD_MAP / patch level'})")

    verdicts = detect_ticket_attacks(events)
    if not verdicts:
        print("no findings (clean, or hashes not mapped yet)")
        return 0
    for v in verdicts:
        print(f"  [{v['tier']:>8}] {v['kind']:<16} account={v['account']!r} ip={v['ip']!r}")
        print(f"             {v['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
