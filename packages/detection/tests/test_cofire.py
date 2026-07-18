"""Co-firing measurement — fire the rule bundle claiming a technique on the synth-enterprise labeled
events and pin the catch-layer divergence. Two regimes:

* single-variant (``variants=("rubeus",)``) — many rules CLAIM kerberoast, few CATCH it, and the catchers
  catch DISJOINT evidence (process vs ticket): claim ≠ catch on data whose labels we control.
* diverse tradecraft (``rubeus``+``powershell``+``setspn``) — diversity surfaces a new catcher (setspn),
  shows a rule is broader than its name (the Rubeus rule also catches PowerShell ``Invoke-Kerberoast`` via
  the ``kerberoast`` token), and EXPOSES coverage gaps: a stealth AES-downgrade evades the RC4 heuristic, so
  more labeled instances go uncaught. seed=1 is deterministic, so the counts are pinnable.
"""

import pytest

from detection.cofire import cofire, cofire_synth
from detection.sigma_panel import SIGMA
from detection.synth.emit import labeled_events
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline

# The cofire_synth tests fire the real Sigma rule bundle at the synth events, so they need the
# vendored corpus (packages/semantic-cyber/data/sigma-rules) — gitignored, absent in CI / clean
# checkouts. Skip when it isn't there, matching test_audit.py / test_atoms.py. (test_cofire_labels_
# partition_events below needs no corpus and stays unguarded.)
_needs_sigma = pytest.mark.skipif(
    not SIGMA.exists(), reason="vendored Sigma corpus (semantic-cyber/data/sigma-rules) not present"
)


@_needs_sigma
def test_single_variant_claim_exceeds_catch_with_disjoint_catchers():
    r = cofire_synth("T1558.003", seed=1, variants=("rubeus",))
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
    # only the 3 authenticate (4768) + 3 lateral logon (4624) instances are caught by neither kerberoast rule
    assert r["instances_caught_by_none"] == 6
    # silent co-claimers fail by impedance OR logic gap — never a faked pass
    assert sum(r["silent_causes"].values()) == r["rules_evaluable"] - r["rules_catching"]


@_needs_sigma
def test_variant_diversity_surfaces_catcher_and_exposes_gaps():
    single = cofire_synth("T1558.003", seed=1, variants=("rubeus",))
    diverse = cofire_synth("T1558.003", seed=1, variants=("rubeus", "powershell", "setspn"))
    rows = {x["rule"]: x for x in diverse["rows"]}
    # diversity surfaces a NEW catcher that the single-variant campaign never exercised
    assert "proc_creation_win_setspn_spn_enumeration.yml" in diverse["clean_catchers"]
    assert "proc_creation_win_setspn_spn_enumeration.yml" not in single["clean_catchers"]
    # the Rubeus rule is broader than its name: it catches the PowerShell Invoke-Kerberoast process too
    assert rows["proc_creation_win_hktl_rubeus.yml"]["n_caught"] >= 2
    # the stealth AES-downgrade evades the RC4 heuristic -> MORE labeled instances uncaught than single-variant
    assert diverse["instances_caught_by_none"] > single["instances_caught_by_none"]
    # still single-witness per instance (no two evaluable rules catch the same event) -> Jaccard 0, a real finding
    assert diverse["mean_pairwise_catch_jaccard"] == 0.0
    assert diverse["instances_caught_by_all_catchers"] == 0
    # every catcher is still clean on the benign background
    assert diverse["catchers_with_fps"] == []


@_needs_sigma
def test_no_downgrade_roast_is_invisible_to_every_signature_rule():
    """The hardest case: a purpose-built-rig attacker requests AES tickets (no RC4 downgrade) with a
    low-signal PowerView footprint. The whole RC4 detection family is blind and no tool-name rule matches,
    so EVERY evaluable kerberoast rule is silent — signature detection goes to exactly zero, and only the
    structural fan-out / SPN→account pivot / cross-host join could catch it."""
    r = cofire_synth("T1558.003", seed=1, variants=("aes_rig",))
    assert r["rules_evaluable"] >= 10            # the rules exist and compile...
    assert r["rules_catching"] == 0              # ...and not one of them catches the no-downgrade roast
    assert r["catch_rate"] == 0.0
    assert r["instances_caught_by_none"] == r["n_malicious"]   # every labeled instance uncaught
    assert "win_security_susp_rc4_kerberos.yml" not in r["clean_catchers"]   # RC4 family blind


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
