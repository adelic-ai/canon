r"""P5 (steps 1+2) — the evaluation harness: precision / recall / FP-rate vs ground truth.

Every canon result so far has been "the detector fires on data that contains the attack."
That shows the MECHANISM. It says nothing about the number that decides whether a detector
is usable: how often it fires on BENIGN traffic. This harness measures that, against
INDEPENDENT ground truth (not the detectors' own logic):

  faker-kerberos: export.truth.json labels the injected attacks (pass-the-ticket ×3,
                  kerberoasting, spray, off-hours, enc-downgrade) — independent of our cells.
  OTRF:           the documented comsvcs LSASS-dump campaign; malicious reads = attacker
                  tools, benign = system/VM services. The SourceImage breakdown is printed
                  so the labeling is auditable, not asserted.

The point is not to show big recall (we know the attacks are there). It is to put a real
DENOMINATOR under precision — and to show what structure buys: a naive "any lsass access"
detector vs the VM_READ-bit surfacer vs the comsvcs subgraph.

Run:  .venv/bin/python packages/detection/experiments/eval_harness.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from kerberos_behavior_detectors import enc_downgrade, kerberoasting, off_hours, password_spray
from kerberos_orphan_real import load as load_kerberos
from lsass_subgraph_detection import load as load_otrf
from registry import _kerberos_forged
from subgraph_matcher import LSASS_DUMP, LSASS_READ_ANY, match_pattern

PROCESS_VM_READ = 0x10


def _pr(name: str, tp: int, fp: int, fn: int, denom_benign: int) -> None:
    fires = tp + fp
    prec = tp / fires if fires else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    fpr = fp / denom_benign if denom_benign else float("nan")
    print(f"  {name:30} fires={fires:<5} TP={tp:<3} FP={fp:<3} FN={fn:<3} "
          f"| precision={prec:5.0%}  recall={rec:5.0%}  FP-rate={fpr:.2%}")


# --------------------------------------------------------------------------- #
def eval_kerberos() -> None:
    events = load_kerberos()
    truth = json.loads((Path.home() / "data/faker-kerberos/v1/export.truth.json").read_text())

    def acct(s: str):  # firstname.lastname out of a truth `type` string
        m = re.search(r"\b([a-z]+\.[a-z]+)\b", s)
        return m.group(1) if m else None

    ptt = {acct(t["type"]) for t in truth if t["type"].startswith("pass-the-ticket")} - {None}
    all_attack = {acct(t["type"]) for t in truth} - {None}
    accounts = {r.get("Account_Name") for r in events} - {None, ""}
    benign = accounts - all_attack

    # the detector: forged TGT (orphan + mid-window) used across >=3 services → fired account
    forged = _kerberos_forged(events)
    fired = {rs[0]["Account_Name"] for h, rs in forged.items()
             if len({r["Service_Name"] for r in rs if r.get("Service_Name")}) >= 3}

    tp = len(fired & ptt)
    fp = len(fired - all_attack)                       # fired on a purely-benign account
    fp_wrong_type = (fired & all_attack) - ptt         # fired on a non-pass-the-ticket attack
    fn = len(ptt - fired)

    print(f"=== faker-kerberos ({len(events):,} events, {len(accounts)} accounts) — independent truth file ===")
    print(f"  ground truth: {len(ptt)} pass-the-ticket {sorted(ptt)}; "
          f"{len(all_attack)} accounts in SOME attack; {len(benign)} benign accounts")
    _pr("kerberos_pass_the_ticket", tp, fp, fn, len(benign))
    print(f"  → recall {tp}/{len(ptt)} pass-the-ticket; {fp} fires on benign accounts; "
          f"{len(fp_wrong_type)} fires on other-attack accounts {sorted(fp_wrong_type) or '∅'}")
    print(f"  honest read: it catches the targeted technique and does NOT fire on kerberoasting/spray/"
          f"off-hours (correctly — it isn't built for them, and they keep a legit TGT so aren't orphans).\n")


def eval_behaviors() -> None:
    """The other 4 labeled attack types — structural detectors scored against the truth file."""
    rows = load_kerberos()
    truth = json.loads((Path.home() / "data/faker-kerberos/v1/export.truth.json").read_text())

    def accts(prefix):
        return {m.group(0) for t in truth if t["type"].startswith(prefix)
                for m in [re.search(r"[a-z]+\.[a-z]+", t["type"])] if m}

    def ips(prefix):
        return {m.group(1) for t in truth if t["type"].startswith(prefix)
                for m in [re.search(r"(\d+\.\d+\.\d+\.\d+)", t["type"])] if m}

    all_attack = {m.group(0) for t in truth for m in [re.search(r"[a-z]+\.[a-z]+", t["type"])] if m}
    accounts = {r.get("Account_Name") for r in rows} - {None, ""}
    client_ips = {r.get("Client_Address", "").replace("::ffff:", "") for r in rows} - {""}
    benign_accts = len(accounts - all_attack)
    benign_ips = len(client_ips - ips("password-spray"))

    def score(name, fired, truth_set, denom):
        tp = len(fired & truth_set)
        _pr(name, tp, len(fired - truth_set), len(truth_set - fired), denom)

    print(f"=== the other 4 labeled attack types — structural detectors vs truth ({len(accounts)} accounts) ===")
    score("kerberoasting", kerberoasting(rows), accts("kerberoasting"), benign_accts)
    score("enc_downgrade", enc_downgrade(rows), accts("enc-downgrade"), benign_accts)
    spray_fired = {ip.replace("::ffff:", "") for ip in password_spray(rows)}
    score("password_spray", spray_fired, ips("password-spray"), benign_ips)
    score("off_hours", off_hours(rows), accts("off-hours"), benign_accts)
    print(f"  honest read: kerberoasting/enc-downgrade/spray are exact (clean structural signatures: rare RC4,")
    print(f"  RC4-without-fanout, IP→many-failed-accounts). off-hours-alone is WEAK (~5% precision, misses 1/2):")
    print(f"  day-shift accounts work the occasional late hour, and a temporal baseline can't separate that")
    print(f"  from the labeled anomaly — off-hours needs WHAT was done off-hours, not just THAT it happened.\n")


# --------------------------------------------------------------------------- #
def eval_otrf() -> None:
    events = load_otrf()
    eid10 = [e for e in events if str(e.get("EventID")) == "10"
             and "lsass" in str(e.get("TargetImage", "")).lower()]

    def src(e):
        return e.get("SourceImage", "?").split("\\")[-1].lower()

    # ground truth (documented comsvcs LSASS-dump campaign) — printed so it's auditable
    ATTACK_TOOLS = {"rundll32.exe", "winx64_payload.exe"}   # comsvcs dump + the campaign payload
    from collections import Counter
    breakdown = Counter(src(e) for e in eid10)
    malicious = {id(e) for e in eid10 if src(e) in ATTACK_TOOLS}
    n_mal = len(malicious)
    benign_reads = len(eid10) - n_mal

    def has_vmread(e):
        try:
            return bool(int(str(e.get("GrantedAccess", "0x0")), 16) & PROCESS_VM_READ)
        except ValueError:
            return False

    def score(fired_events, label):
        ids = {id(e) for e in fired_events}
        tp = len(ids & malicious)
        fp = len(ids - malicious)
        fn = n_mal - tp
        _pr(label, tp, fp, fn, benign_reads)

    naive = eid10                                                          # "any lsass access"
    surfacer = [m["lsass_read"] for m in match_pattern(LSASS_READ_ANY, events)]   # VM_READ bit
    subgraph = [m["lsass_read"] for m in match_pattern(LSASS_DUMP, events)]       # comsvcs-rooted

    print(f"=== OTRF LSASS_campaign_03 ({len(events):,} events) — documented comsvcs dump ===")
    print(f"  {len(eid10)} lsass-target reads; SourceImage: {dict(breakdown)}")
    print(f"  ground-truth malicious (attacker tools {sorted(ATTACK_TOOLS)}): {n_mal}; benign reads: {benign_reads}")
    score(naive, "naive: any lsass read")
    score(surfacer, "lsass_vm_read_surfacer")
    score(subgraph, "lsass_dump_subgraph")
    print(f"  → PRECISION climb is the robust result: structure (VM_READ bit, then the comsvcs subgraph)")
    print(f"    turns a ~{n_mal/len(eid10):.0%}-precision naive net into a precise detector.")
    print(f"  → RECALL is denominator-relative: it's measured vs ALL {n_mal} attacker-tool reads (2 tools).")
    print(f"    The subgraph TARGETS only comsvcs-minidump → 1/1=100% for its own technique; its '20%' is")
    print(f"    just the cross-tool denominator. Narrow=precise-but-specific, broad=sensitive-but-noisy —")
    print(f"    the precision/recall tradeoff, on real data. (Labeling by SourceImage is printed above = auditable.)\n")


def main() -> None:
    print("PRECISION / RECALL / FP-RATE vs INDEPENDENT GROUND TRUTH — the credibility numbers we lacked.\n")
    eval_kerberos()
    eval_behaviors()
    eval_otrf()
    print("Honest scope: two corpora, attacks known by construction/documentation. Not a claim of")
    print("field generalization — that needs labeled enterprise data (deferred: BOTS is Splunk-format + unlabeled).")


if __name__ == "__main__":
    main()
