"""Cross-host join (L5 payoff) — validated on the generated multi-log dataset. The join catches the
kerberoast→lateral campaigns (recall, zero FP) that the PER-ACTOR chain checker structurally misses, because
the pivot crosses accounts. This is the whole reason the synthetic test stand exists."""

from detection.chain import check_chain, stage_authenticate, stage_rc4_fanout, stage_sensitive_logon
from detection.cross_host import kerberoast_lateral_join
from detection.evtx_xml import _parse_event
from detection.synth.emit import project_timeline
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline

_INV = build_inventory(seed=1)


def _dataset(seed=8, **kw):
    """Generate → project → round-trip → the union of all multi-log events + the causal labels."""
    acts = build_timeline(_INV, seed=seed, **kw)
    logs = project_timeline(acts, _INV)
    events = [_parse_event(x) for lines in logs.values() for x in lines]
    roasters = {a.label.split("kerberoast:")[1] for a in acts if a.label}
    return events, roasters


def test_cross_host_join_recall_and_zero_fp():
    events, roasters = _dataset(seed=8, n_kerberoasters=3, roast_fanout=10)
    dets = kerberoast_lateral_join(events, spn_to_account=_INV.spn_to_account(),
                                   sensitive_hosts=_INV.sensitive_hosts(), n=8)
    caught = {d["roaster"] for d in dets}
    assert caught == roasters                               # every campaign caught…
    for d in dets:
        assert d["roaster"] in roasters                     # …no false positive
        assert d["cracked_account"] != d["roaster"]         # the pivot is genuinely cross-account
        assert d["target_host"] in _INV.sensitive_hosts()
        assert d["roast_time"] <= d["logon_time"]           # roast then pivot


def test_per_actor_chain_misses_what_the_join_catches():
    """The contrast that justifies the join: the SAME 3-stage spec, run PER ACTOR over the same data, does NOT
    flag the roasters — the lateral logon is under the cracked service account, a different actor.

    Isolated with ``benign_server_logon_p=0`` so the only sensitive-host logons are the cross-account pivots.
    (With benign sensitive logons present, per-actor can instead fire on a roaster for the WRONG reason — their
    OWN coincidental benign logon after the roast — which is a false attribution, not a real catch of the
    pivot. Either way per-actor cannot correctly attribute the cross-account chain; the join can.)"""
    events, roasters = _dataset(seed=8, n_kerberoasters=3, roast_fanout=10, benign_server_logon_p=0.0)
    three_stage = [
        ("authenticate", lambda evs, nb: stage_authenticate(evs, nb, code_field="EventID", tgt_code="4768",
                                                            time_field="TimeCreated")),
        ("rc4_fanout", lambda evs, nb: stage_rc4_fanout(evs, nb, n=8, code_field="EventID", tgs_code="4769",
                                                        enc_field="TicketEncryptionType", rc4="0x17",
                                                        svc_field="ServiceName", time_field="TimeCreated")),
        ("sensitive_logon", lambda evs, nb: stage_sensitive_logon(
            evs, nb, sensitive_hosts=_INV.sensitive_hosts(), code_field="EventID", logon_code="4624",
            host_field="Computer", logontype_field="LogonType", time_field="TimeCreated")),
    ]
    per_actor = set(check_chain(events, three_stage, actor_field="TargetUserName")["satisfied"])
    # the per-actor 3-stage flags NONE of the roasters (their sensitive_logon is under the svc account)
    assert not (per_actor & roasters)
    # but the cross-host join catches them all — the capability gap, demonstrated on faithful data
    join = {d["roaster"] for d in kerberoast_lateral_join(
        events, spn_to_account=_INV.spn_to_account(), sensitive_hosts=_INV.sensitive_hosts(), n=8)}
    assert join == roasters


def test_benign_only_dataset_yields_no_detections():
    events, roasters = _dataset(seed=5, n_kerberoasters=0, benign_server_logon_p=1.0)
    assert roasters == set()
    dets = kerberoast_lateral_join(events, spn_to_account=_INV.spn_to_account(),
                                   sensitive_hosts=_INV.sensitive_hosts(), n=8)
    assert dets == []                                       # benign (AES tickets, no cross-account pivot) → silent
