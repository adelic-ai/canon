"""Projection — render each L2 activity into the WinEventLog XML of the log it touches (L3).

This is where the single activity timeline becomes the **multiple interconnected logs**. Each activity emits
ONE event on ONE host's log, in faithful one-``<Event>``-per-line WinEventLog XML (the exact shape
:mod:`detection.evtx_xml` ingests — real ``<Data Name='…'>`` field names, no toy dicts). The interconnection is
not a field — it's the **shared keys** the projection writes consistently:

- ``IpAddress`` = the actor's source-host IP (resolved from the inventory — the single source of IP truth),
- ``TargetUserName`` = the actor, ``ServiceName`` = the requested SPN, ``Computer`` = the host whose log it is.

So a roast's 4769 on the DC carries ``IpAddress`` = the workstation, the lateral 4624 on the crown jewel carries
the *same* ``IpAddress`` (different account — the cracked service account), and the workstation's Sysmon process
carries that host. The cross-host **and** cross-account join (same IP + SPN→account) is reconstructable from the
emitted data — which is exactly what the per-actor chain checker *cannot* see and the cross-host accumulator can.

Mapping: ``authenticate`` → 4768 (DC) · ``request_ticket`` → 4769 (DC) · ``logon`` → 4624 (destination host) ·
``process_create`` → Sysmon EventID 1 (source host). Round-trips through :func:`detection.evtx_xml.load_evtx_xml`.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from detection.synth.inventory import Inventory
from detection.synth.timeline import Activity

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_SECURITY = "Security"
_SYSMON = "Microsoft-Windows-Sysmon/Operational"
_TICKET_OPTIONS = "0x40810000"     # a typical kerberos ticket-options bitmask


def _iso(t: float) -> str:
    """Event time as EVTX SystemTime (UTC, microseconds, trailing Z) — what ``TimeCreated`` carries."""
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _event_xml(*, event_id: int, computer: str, channel: str, time: float, provider: str,
               data: dict[str, str | None]) -> str:
    """One faithful ``<Event>`` line: ``<System>`` (provider/id/time/channel/computer) + ``<EventData>`` of
    ``<Data Name='X'>v</Data>`` pairs. ``None`` values are dropped."""
    system = (f"<System><Provider Name='{escape(provider)}'/><EventID>{event_id}</EventID>"
              f"<TimeCreated SystemTime='{_iso(time)}'/><Channel>{escape(channel)}</Channel>"
              f"<Computer>{escape(computer)}</Computer></System>")
    eventdata = "<EventData>" + "".join(
        f"<Data Name='{escape(k)}'>{escape(str(v))}</Data>" for k, v in data.items() if v is not None
    ) + "</EventData>"
    return f"<Event xmlns='{_NS}'>{system}{eventdata}</Event>"


def project_activity(a: Activity, inv: Inventory, *, ticket_hashes: bool = False) -> tuple[str, str, str] | None:
    """Project one activity → ``(host, channel, xml_line)`` — the host whose log carries the event — or ``None``
    if the action emits no log event. IPs are resolved from the inventory so the shared keys line up.
    ``ticket_hashes`` models a 2024-patched DC: when True, 4768/4769 carry the Ticket Information hash fields
    (:data:`detection.kerberos_tickets.REQUEST_TICKET_HASH` / ``RESPONSE_TICKET_HASH``); when False (default,
    an unpatched DC) those fields are absent — exactly the tier the ticket detector must fall back through."""
    from detection.kerberos_tickets import REQUEST_TICKET_HASH, RESPONSE_TICKET_HASH, SERVICE_TICKET_HASH

    src_ip = inv.host_by_name(a.src_host).ip if a.src_host and inv.host_by_name(a.src_host) else None
    dc = next(h.name for h in inv.hosts if h.kind == "dc")

    if a.action == "authenticate":                      # 4768 TGT-request, logged on the DC
        data = {"TargetUserName": a.actor, "IpAddress": src_ip, "TicketEncryptionType": a.attr("enc")}
        if ticket_hashes:
            data[RESPONSE_TICKET_HASH] = a.attr("tgt_hash")     # the issued TGT
        return dc, _SECURITY, _event_xml(
            event_id=4768, computer=dc, channel=_SECURITY, time=a.time,
            provider="Microsoft-Windows-Security-Auditing", data=data)

    if a.action == "request_ticket":                    # 4769 TGS-request, logged on the DC
        data = {"TargetUserName": a.actor, "ServiceName": a.target,
                "TicketEncryptionType": a.attr("enc"), "TicketOptions": _TICKET_OPTIONS, "IpAddress": src_ip}
        if ticket_hashes:
            data[REQUEST_TICKET_HASH] = a.attr("tgt_hash")      # the TGT presented (real 4769 name: RequestTicketHash)
            data[SERVICE_TICKET_HASH] = a.attr("tgs_hash")      # the issued service ticket (real 4769 name: ResponseTicketHash)
        return dc, _SECURITY, _event_xml(
            event_id=4769, computer=dc, channel=_SECURITY, time=a.time,
            provider="Microsoft-Windows-Security-Auditing", data=data)

    if a.action == "logon":                             # 4624 logon, logged on the DESTINATION host
        dst = a.dst_host or a.src_host
        return dst, _SECURITY, _event_xml(
            event_id=4624, computer=dst, channel=_SECURITY, time=a.time,
            provider="Microsoft-Windows-Security-Auditing",
            data={"TargetUserName": a.actor, "LogonType": a.attr("logon_type"),
                  "IpAddress": src_ip, "WorkstationName": a.src_host})

    if a.action == "process_create":                    # Sysmon EventID 1, logged on the SOURCE host
        return a.src_host, _SYSMON, _event_xml(
            event_id=1, computer=a.src_host, channel=_SYSMON, time=a.time,
            provider="Microsoft-Windows-Sysmon",
            data={"Image": a.attr("image"), "CommandLine": a.attr("cmdline") or a.attr("image"),
                  "User": a.actor, "ProcessGuid": a.attr("guid")})

    return None


def project_timeline(acts: list[Activity], inv: Inventory) -> dict[tuple[str, str], list[str]]:
    """Project a whole timeline → the separate interconnected log streams, keyed by ``(host, channel)``. Each
    value is a list of one-``<Event>``-per-line XML strings, in timeline order. This *is* the multi-log dataset:
    DC Security (4768/4769/4624), each crown-jewel's Security (4624), each workstation's Sysmon (process)."""
    logs: dict[tuple[str, str], list[str]] = defaultdict(list)
    for a in acts:
        p = project_activity(a, inv)
        if p is not None:
            host, channel, xml = p
            logs[(host, channel)].append(xml)
    return dict(logs)


def labeled_events(acts: list[Activity], inv: Inventory, *,
                   ticket_hashes: bool = False) -> list[tuple[dict, str | None]]:
    """Project the timeline to flat event-dicts paired with each activity's causal ground-truth ``label``
    (``None`` = benign, ``kerberoast:<user>`` = a campaign step). The same events :func:`project_timeline`
    writes to log files, but parsed back to the dicts the Sigma evaluator consumes and carrying the label
    instead of being grouped by ``(host, channel)``. This is the labeled view :mod:`detection.cofire`
    fires the rule bundle against — the round-trip through :func:`detection.evtx_xml` keeps it faithful
    (real ``<Data Name=…>`` field names, no toy dicts)."""
    from detection.evtx_xml import _parse_event

    out: list[tuple[dict, str | None]] = []
    for a in acts:
        p = project_activity(a, inv, ticket_hashes=ticket_hashes)
        if p is None:
            continue
        e = _parse_event(p[2])
        if e is not None:
            out.append((e, a.label))
    return out


def write_logs(logs: dict[tuple[str, str], list[str]], out_dir: str | Path) -> dict[tuple[str, str], Path]:
    """Write each ``(host, channel)`` stream to ``out_dir/<host>__<channel>.xml`` (one Event per line). Returns
    the paths. Data destination is a workspace dir (``~/data``); this is the only I/O in the generator."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[tuple[str, str], Path] = {}
    for (host, channel), lines in logs.items():
        fname = f"{host}__{channel.replace('/', '-')}.xml"
        p = out / fname
        p.write_text("\n".join(lines) + "\n")
        paths[(host, channel)] = p
    return paths
