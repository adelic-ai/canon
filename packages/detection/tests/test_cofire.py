"""Co-firing measurement — fire the rule bundle claiming a technique on the synth-enterprise labeled
events and pin the catch-layer divergence. The load-bearing fact: many rules CLAIM kerberoast, few CATCH
it, and the catchers catch DISJOINT evidence (process vs ticket) — claim ≠ catch, made concrete on data
whose labels we control. Structural assertions (not exact corpus counts) so SigmaHQ drift doesn't break them.
"""

from detection.cofire import cofire, cofire_synth
from detection.synth.emit import labeled_events
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline


def test_kerberoast_claim_exceeds_catch_with_disjoint_catchers():
    r = cofire_synth("T1558.003", seed=1)
    # many rules claim the technique, only a few actually catch the synth roast (the claim≠catch gap)
    assert r["rules_evaluable"] >= 10
    assert 0 < r["rules_catching"] < r["rules_evaluable"]
    assert r["catch_rate"] < 0.4
    # the two faithful catchers fire on the raw-Windows surfaces the synth emits, with zero benign FP
    assert "win_security_susp_rc4_kerberos.yml" in r["clean_catchers"]   # 4769 RC4 ticket
    assert "proc_creation_win_hktl_rubeus.yml" in r["clean_catchers"]    # Rubeus process
    assert r["catchers_with_fps"] == []
    # they catch NON-OVERLAPPING evidence (ticket events vs process events) -> Jaccard 0, none caught by all
    assert r["mean_pairwise_catch_jaccard"] == 0.0
    assert r["instances_caught_by_all_catchers"] == 0
    # the authenticate (4768) + lateral logon (4624) instances are caught by neither kerberoast rule
    assert r["instances_caught_by_none"] >= 1
    # silent co-claimers fail by impedance OR logic gap — never a faked pass
    assert sum(r["silent_causes"].values()) == r["rules_evaluable"] - r["rules_catching"]


def test_cofire_labels_partition_events():
    inv = build_inventory(seed=1)
    acts = build_timeline(inv, seed=1)
    pairs = labeled_events(acts, inv)
    events = [e for e, _ in pairs]
    labels = [lab for _, lab in pairs]
    assert any(labels) and not all(labels)            # both malicious and benign present
    r = cofire("T1558.003", events, labels)
    assert r["n_malicious"] + r["n_benign"] == len(events)
    assert r["n_malicious"] == sum(1 for lab in labels if lab)
