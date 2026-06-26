"""Projection layer (L3) — the single timeline becomes the multiple interconnected logs, in real WinEventLog
XML. Tests pin: faithful round-trip through canon's own evtx_xml parser (incl. the TimeCreated fix), the logs
are separated by (host, channel), the cross-host + cross-account JOIN KEYS line up across logs, and canon's
real (parameterized) chain checker runs on the round-tripped real-schema data.
"""

from detection.chain import check_chain, stage_authenticate, stage_rc4_fanout
from detection.evtx_xml import _parse_event
from detection.synth.emit import project_activity, project_timeline, write_logs
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline

_INV = build_inventory(seed=1)


def _roundtrip(acts):
    """Project → parse every emitted line back through evtx_xml → events grouped by (host, channel)."""
    logs = project_timeline(acts, _INV)
    return {hc: [_parse_event(x) for x in lines] for hc, lines in logs.items()}


def test_every_emitted_line_roundtrips_with_timecreated():
    acts = build_timeline(_INV, seed=3)
    logs = project_timeline(acts, _INV)
    n = 0
    for (host, channel), lines in logs.items():
        for x in lines:
            e = _parse_event(x)
            assert e is not None and e["EventID"] and e["Computer"] == host
            assert e["Channel"] == channel
            assert "TimeCreated" in e and e["TimeCreated"].endswith("Z")    # the evtx_xml TimeCreated fix
            n += 1
    assert n > 0


def test_logs_are_separated_by_host_and_channel():
    acts = build_timeline(_INV, seed=4)
    logs = project_timeline(acts, _INV)
    dc = next(h.name for h in _INV.hosts if h.kind == "dc")
    # DC Security carries TGT/TGS; some workstation Sysmon carries the process; ≥2 distinct hosts emit logs
    assert (dc, "Security") in logs
    eids_on_dc = {_parse_event(x)["EventID"] for x in logs[(dc, "Security")]}
    assert {"4768", "4769"} <= eids_on_dc
    assert any(ch == "Microsoft-Windows-Sysmon/Operational" for _h, ch in logs)
    assert len({h for h, _c in logs}) >= 2


def test_join_keys_line_up_across_logs():
    """The cross-host + cross-account join is reconstructable from the emitted data: a roast's 4769 on the DC
    and the lateral 4624 on the crown jewel share the workstation IP, and the roasted SPN's account is the
    4624's account (a DIFFERENT account — the pivot)."""
    acts = build_timeline(_INV, seed=8, n_kerberoasters=2)
    rt = _roundtrip(acts)
    dc = next(h.name for h in _INV.hosts if h.kind == "dc")
    spn_to_acct = _INV.spn_to_account()
    dc_4769 = [e for e in rt[(dc, "Security")] if e["EventID"] == "4769" and e["TicketEncryptionType"] == "0x17"]

    checked = 0
    for label in {a.label for a in acts if a.label}:
        roaster = label.split("kerberoast:")[1]
        ws_ip = _INV.user_ip(roaster)
        # the cracked account = a roasted crackable SPN's account, found in the roast events from this WS
        roasted = {e["ServiceName"] for e in dc_4769 if e["IpAddress"] == ws_ip and e["TargetUserName"] == roaster}
        cracked_accts = {spn_to_acct[s] for s in roasted if s in spn_to_acct}
        # find the lateral 4624 on a crown jewel, same WS IP, as one of those accounts
        for (host, _ch), evs in rt.items():
            for e in evs:
                if (e["EventID"] == "4624" and e.get("IpAddress") == ws_ip
                        and e["TargetUserName"] in cracked_accts and host in _INV.sensitive_hosts()):
                    assert e["TargetUserName"] != roaster          # cross-account pivot
                    checked += 1
    assert checked >= 1, "no cross-host/cross-account lateral logon reconstructable from the join keys"


def test_real_chain_checker_runs_on_roundtripped_schema():
    """Canon's existing chain checker fires on the real-schema (round-tripped) DC log via field parameters —
    the 2-stage roast is per-actor, so it fires on the roasters. (The 3-stage lateral is cross-account and does
    NOT fire per-actor — the documented gap the cross-host accumulator closes.)"""
    acts = build_timeline(_INV, seed=8, n_kerberoasters=3, roast_fanout=10)
    rt = _roundtrip(acts)
    dc = next(h.name for h in _INV.hosts if h.kind == "dc")
    dc_events = rt[(dc, "Security")]
    roasters = {a.label.split("kerberoast:")[1] for a in acts if a.label}

    real_field_stages = [
        ("authenticate", lambda evs, nb: stage_authenticate(evs, nb, code_field="EventID", tgt_code="4768",
                                                            time_field="TimeCreated")),
        ("rc4_fanout", lambda evs, nb: stage_rc4_fanout(evs, nb, n=8, code_field="EventID", tgs_code="4769",
                                                        enc_field="TicketEncryptionType", rc4="0x17",
                                                        svc_field="ServiceName", time_field="TimeCreated")),
    ]
    res = check_chain(dc_events, real_field_stages, actor_field="TargetUserName")
    fired = set(res["satisfied"])
    assert roasters <= fired                                       # every roaster's 2-stage roast fires
    # benign users do not fan out RC4 → not flagged
    assert not (fired - roasters)


def test_write_logs_roundtrips_from_disk(tmp_path):
    acts = build_timeline(_INV, seed=2)
    from detection.evtx_xml import load_evtx_xml
    paths = write_logs(project_timeline(acts, _INV), tmp_path)
    assert paths
    some = next(iter(paths.values()))
    events = load_evtx_xml(some)
    assert events and all("EventID" in e for e in events)
