"""End-to-end demonstration of the synthetic enterprise stand (L1–L5): build a correlated, causally-labeled,
multi-log dataset and detect the kerberoast→lateral campaigns with the CROSS-HOST join — the chain the per-actor
checker structurally can't see. Self-contained (no external data): the generator IS the data.

Run:  uv run python packages/detection/experiments/synth_cross_host_demo.py
Optionally writes the WinEventLog XML logs to ~/data/synth-enterprise/ (workspace; not committed).
"""

from pathlib import Path

from detection.chain import check_chain, stage_authenticate, stage_rc4_fanout, stage_sensitive_logon
from detection.cross_host import kerberoast_lateral_join
from detection.evtx_xml import _parse_event
from detection.synth.emit import project_timeline, write_logs
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline
from detection.synth.validate import separability_report


def main() -> None:
    inv = build_inventory(seed=1, n_users=40, n_workstations=15)
    acts = build_timeline(inv, seed=8, days=5, n_kerberoasters=3, roast_fanout=10)
    logs = project_timeline(acts, inv)
    events = [_parse_event(x) for lines in logs.values() for x in lines]
    roasters = {a.label.split("kerberoast:")[1] for a in acts if a.label}

    print(f"inventory: {len(inv.hosts)} hosts, {len(inv.users)} users, {len(inv.service_accounts)} svc accounts")
    print(f"timeline:  {len(acts)} activities ({sum(1 for a in acts if a.label)} attack-labeled)")
    print(f"logs:      {len(logs)} interconnected streams (host, channel):")
    for (host, channel), lines in sorted(logs.items()):
        print(f"             {host:24} {channel:38} {len(lines):4} events")

    rep = separability_report(events, sensitive_hosts=inv.sensitive_hosts())
    print(f"\nseparability: {rep['single_origin_accounts']}/{rep['n_accounts']} accounts single-origin "
          f"(benign coherent); naive correlation flags {rep['naive_correlation_flagged_ips']} IPs "
          f"(over-fires — can't isolate the attacker)")

    three = [
        ("authenticate", lambda e, nb: stage_authenticate(e, nb, code_field="EventID", tgt_code="4768",
                                                          time_field="TimeCreated")),
        ("rc4_fanout", lambda e, nb: stage_rc4_fanout(e, nb, n=8, code_field="EventID", tgs_code="4769",
                                                      enc_field="TicketEncryptionType", rc4="0x17",
                                                      svc_field="ServiceName", time_field="TimeCreated")),
        ("sensitive_logon", lambda e, nb: stage_sensitive_logon(
            e, nb, sensitive_hosts=inv.sensitive_hosts(), code_field="EventID", logon_code="4624",
            host_field="Computer", logontype_field="LogonType", time_field="TimeCreated")),
    ]
    per_actor = set(check_chain(events, three, actor_field="TargetUserName")["satisfied"]) & roasters
    dets = kerberoast_lateral_join(events, spn_to_account=inv.spn_to_account(),
                                   sensitive_hosts=inv.sensitive_hosts(), n=8)
    caught = {d["roaster"] for d in dets}

    print(f"\nground-truth kerberoasters: {sorted(roasters)}")
    print(f"per-actor 3-stage (chain.py) flags: {sorted(per_actor)}  ← cannot attribute the cross-account "
          f"pivot (the lateral logon is under the cracked account); any hit here is a wrong-reason firing on "
          f"the roaster's OWN benign logon, not a real catch")
    print(f"cross-host join: recall {len(caught & roasters)}/{len(roasters)}  FP {len(caught - roasters)}")
    for d in sorted(dets, key=lambda d: d["roaster"]):
        mins = (d["logon_time"] - d["roast_time"]) / 60.0
        print(f"   {d['roaster']:22} roasts {len(d['roasted_spns'])} SPNs from {d['src_ip']:11} → "
              f"{d['cracked_account']} logs into {d['target_host']} (+{mins:.0f} min, cross-account)")

    out = Path.home() / "data" / "synth-enterprise"
    paths = write_logs(logs, out)
    print(f"\nwrote {len(paths)} log files to {out} (workspace; local only)")


if __name__ == "__main__":
    main()
