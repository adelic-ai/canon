"""Load Windows EVTX events exported as one-``<Event>``-per-line XML into the flat event-dicts the Sigma
evaluator consumes.

The splunk/attack_data ``windows-xml.log`` files (and the EVTX-ATTACK-SAMPLES corpora, once dumped to XML)
carry events in the native EVTX XML shape: ``<System>`` metadata + an ``<EventData>`` block of
``<Data Name='Field'>value</Data>`` pairs whose ``Name`` attributes ARE the Sigma field names (``ServiceName``,
``TicketEncryptionType``, …) — no impedance to normalize, unlike the Splunk text-export key/value shape. So
this is the faithful, low-translation ingest: ``EventID`` + ``Channel``/``Computer`` + every ``Data`` field,
flattened to one dict per event. Stdlib ``xml.etree`` only — no new dependency.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _parse_event(line: str) -> dict | None:
    """One ``<Event>`` XML line → a flat field dict. ``EventID``/``Channel``/``Computer`` from ``<System>``;
    every ``<Data Name='X'>v</Data>`` from ``<EventData>`` as ``{X: v}``. Returns ``None`` on a non-event/
    unparseable line (robust to blank lines and stray text in a log)."""
    line = line.strip()
    if not line.startswith("<Event"):
        return None
    try:
        root = ET.fromstring(line)
    except ET.ParseError:
        return None
    out: dict[str, str] = {}
    sys = root.find(f"{_NS}System")
    if sys is not None:
        for tag in ("EventID", "Channel", "Computer"):
            el = sys.find(f"{_NS}{tag}")
            if el is not None and el.text is not None:
                out[tag] = el.text
        # TimeCreated carries the event time in its SystemTime *attribute* (not text) — capture it, since any
        # temporal detection (windows, ordering, the chain checker's not_before) needs it. Absent in some
        # exports, so it is best-effort.
        tc = sys.find(f"{_NS}TimeCreated")
        if tc is not None and tc.get("SystemTime"):
            out["TimeCreated"] = tc.get("SystemTime")
    data = root.find(f"{_NS}EventData")
    if data is not None:
        for d in data.findall(f"{_NS}Data"):
            name = d.get("Name")
            if name:
                out[name] = d.text if d.text is not None else ""
    return out


def load_evtx_xml(path: str | Path) -> list[dict]:
    """Parse a one-``<Event>``-per-line EVTX XML log into flat event-dicts (skipping unparseable lines)."""
    text = Path(path).read_text(errors="replace")
    return [e for line in text.splitlines() if (e := _parse_event(line)) is not None]
