r"""Rung-3 two-paradigm unification, generalized: cross_check over multiple techniques.

The second case forces the abstraction. One statistical detector (`SERVICE_TICKET_FANOUT`) is
technique-BLIND — it flags "one account, many service tickets" without knowing whether that's
kerberoasting or pass-the-ticket. Two structural SIGNATURES disambiguate it:

  kerberoasting (T1558.003)   signature = many distinct RC4 service tickets
  pass-the-ticket (T1550.003) signature = an orphan TGT (no issuing 4768) fanning out

cross_check = kjoin(structural, statistical) per (account, technique). Each structural verdict is
THREE-valued so disagreement (FALSE∧TRUE→both) fires instead of silently agreeing (NONE∧TRUE→true):
  TRUE  = the signature is present
  FALSE = the account fanned out but WITHOUT this signature (definitively not this technique)
  NONE  = it didn't fan out (structural abstains)

Run against the SAME statistical anomaly set, the two cross_checks SORT the technique-blind fan-out
anomalies into their real techniques, and cross_check=both flags every mismatch. Calls the
statistical detector from `detection` (proper) — experiments-calls-proper. Promotion into the
verdict envelope is #5.

Run:  .venv/bin/python packages/detection/experiments/cross_check.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from detection import PASSWORD_SPRAY, SERVICE_TICKET_FANOUT, run_binding
from kerberos_orphan_real import load
from lsass_subgraph_detection import cid
from provenance import BOTH, FALSE, NONE, TRUE, kjoin

RC4 = "0x17"
CSV = str(Path.home() / "data/faker-kerberos/v1/export.csv")
_S = {TRUE: "true", FALSE: "false", NONE: "none", BOTH: "both"}


def structural_kerberoast(rows, min_services: int = 10) -> dict:
    """RC4 fan-out signature. TRUE: >=min RC4 services. FALSE: fanned out but not via RC4. NONE: no fan-out."""
    rc4, allsvc = defaultdict(set), defaultdict(set)
    for r in rows:
        if r.get("EventCode") == "4769":
            allsvc[r["Account_Name"]].add(r.get("Service_Name", ""))
            if r.get("Ticket_Encryption_Type") == RC4:
                rc4[r["Account_Name"]].add(r.get("Service_Name", ""))
    out = {}
    for a in allsvc:
        if len(rc4[a]) >= min_services:
            out[a] = (TRUE, {"rc4_services": len(rc4[a])})
        elif len(allsvc[a]) >= min_services:
            out[a] = (FALSE, {"rc4_services": len(rc4[a]), "total_services": len(allsvc[a])})
        else:
            out[a] = (NONE, {})
    return out


def structural_ptt(rows, min_orphan: int = 3, fanout_floor: int = 10) -> dict:
    """Orphan-TGT fan-out signature. TRUE: an orphan TGT (no issuing 4768) fanning >=min_orphan services.
    FALSE: fanned out (>=fanout_floor) but on a LEGIT TGT (not orphan). NONE: no fan-out."""
    issued = {r["Ticket_Hash"] for r in rows if r.get("EventCode") == "4768" and r.get("Ticket_Hash")}
    orphan, allsvc = defaultdict(set), defaultdict(set)
    for r in rows:
        if r.get("EventCode") == "4769":
            a = r["Account_Name"]
            allsvc[a].add(r.get("Service_Name", ""))
            if r.get("Ticket_Hash") and r["Ticket_Hash"] not in issued:
                orphan[a].add(r.get("Service_Name", ""))
    out = {}
    for a in allsvc:
        if len(orphan[a]) >= min_orphan:
            out[a] = (TRUE, {"orphan_services": len(orphan[a])})
        elif len(allsvc[a]) >= fanout_floor:
            out[a] = (FALSE, {"orphan_services": len(orphan[a]), "total_services": len(allsvc[a])})
        else:
            out[a] = (NONE, {})
    return out


def statistical(csv: str, binding) -> tuple[dict, float]:
    """entity -> best (lowest) conformal p-value under `binding`, plus the FAR bound alpha.
    The statistical detector is a parameter too — same engine, different entity/value/grain."""
    r = run_binding(csv, binding)
    by_entity: dict[str, float] = {}
    for d in r["detected"]:
        e = d.cell.entity.replace("::ffff:", "")
        by_entity[e] = min(by_entity.get(e, 1.0), d.pvalue)
    return by_entity, r["alpha"]


def structural_spray(rows, min_accounts: int = 10) -> dict:
    """Source-IP spray signature. TRUE: >=min_accounts distinct accounts FAILED auth from this IP.
    FALSE: the IP touched >=min_accounts accounts but without the failure pattern. NONE: few accounts."""
    fail, allacct = defaultdict(set), defaultdict(set)
    for r in rows:
        ip = r.get("Client_Address", "").replace("::ffff:", "")
        if not ip:
            continue
        allacct[ip].add(r.get("Account_Name", ""))
        if r.get("Failure_Code") == "0x18" or r.get("Status") == "0x18":
            fail[ip].add(r.get("Account_Name", ""))
    out = {}
    for ip in allacct:
        if len(fail[ip]) >= min_accounts:
            out[ip] = (TRUE, {"failed_accounts": len(fail[ip])})
        elif len(allacct[ip]) >= min_accounts:
            out[ip] = (FALSE, {"failed_accounts": len(fail[ip]), "total_accounts": len(allacct[ip])})
        else:
            out[ip] = (NONE, {})
    return out


def combined_verdict(acct, technique, sv, ev, stat_p, alpha, cc) -> dict:
    subject = cid({"technique": technique, "account": acct})
    return {
        "technique": technique, "decision": _S[cc], "cross_check": _S[cc],
        "score": round(1 - stat_p, 5) if stat_p is not None else 1.0,
        "calibration": {"method": "conformal", "far_bound": alpha} if stat_p is not None else None,
        "guarantee": {"tier": "well-formed", "subject_cid": subject}, "provenance": subject,
        "evidence": {
            "structural": {"verdict": _S[sv], **ev},
            "statistical": {"verdict": "true" if stat_p is not None else "none", "pvalue": stat_p, "far_bound": alpha},
        },
    }


def run_cross_check(name, technique, struct, stat, alpha) -> dict:
    actionable = {a for a, (v, _) in struct.items() if v == TRUE} | set(stat)
    correct_neg = sum(1 for a, (v, _) in struct.items() if v == FALSE and a not in stat)
    print(f"\n=== cross_check: {name} ({technique}), FAR α={alpha} ===")
    print(f"  {'account':18} {'structural':10} {'statistical':14} {'cross_check':11} reading")
    result = {"true": [], "both": []}
    for a in sorted(actionable):
        sv = struct.get(a, (NONE, {}))[0]
        stv = TRUE if a in stat else NONE
        cc = kjoin(sv, stv)
        p = stat.get(a)
        reading = {"true": "corroborated" if sv == TRUE else "statistical-only",
                   "both": f"ALARM: stat=fanout, struct says NOT {name} → other technique",
                   "false": "structural-only", "none": "—"}[_S[cc]]
        print(f"  {a:18} {_S[sv]:10} {('p=%.5f' % p) if p else '—':14} {_S[cc]:11} {reading}")
        if _S[cc] in result:
            result[_S[cc]].append(a)
    print(f"  (+ {correct_neg} fanned-out-via-other-signature, no outlier → false, correctly not {name} — suppressed)")
    return result


def main() -> None:
    rows = load()
    stat, alpha = statistical(CSV, SERVICE_TICKET_FANOUT)
    print(f"one technique-blind statistical fan-out detector flagged {len(stat)} accounts: {sorted(stat)}")
    print("two structural signatures cross-check it to resolve WHICH technique each is:")

    k = run_cross_check("kerberoasting", "T1558.003", structural_kerberoast(rows), stat, alpha)
    p = run_cross_check("pass-the-ticket", "T1550.003", structural_ptt(rows), stat, alpha)

    # third case: different entity type (source IP) + different statistical binding (PASSWORD_SPRAY)
    spray_stat, spray_alpha = statistical(CSV, PASSWORD_SPRAY)
    run_cross_check("password-spray", "T1110.003", structural_spray(rows), spray_stat, spray_alpha)

    print("\n=== disambiguation summary ===")
    print(f"  kerberoasting corroborated: {sorted(k['true'])}")
    print(f"  pass-the-ticket corroborated: {sorted(p['true'])}")
    both_tech = sorted(set(k["true"]) & set(p["true"]))
    print(f"  BOTH techniques (orphan TGT + RC4 fan-out): {both_tech}")
    print(f"  kerberoast alarms (stat said kerberoast, really PTT): {sorted(k['both'])}")
    print(f"  ptt alarms (stat said PTT, really kerberoast): {sorted(p['both'])}")
    print("\nThe technique-blind statistical fan-out is sorted into real techniques by the structural")
    print("signatures; every cross_check=both is the statistical detector's ambiguity, surfaced not buried.")

    # one combined verdict each way
    a = "maria.montgomery"
    sk = structural_kerberoast(rows)[a]
    print(f"\n--- corroborated verdict ({a}, kerberoasting) — one envelope, why + FAR ---")
    print(json.dumps(combined_verdict(a, "T1558.003", sk[0], sk[1], stat.get(a), alpha, kjoin(sk[0], TRUE)), indent=2))


if __name__ == "__main__":
    main()
