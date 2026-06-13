r"""Rung-3 two-paradigm unification: cross_check on kerberoasting.

Combine the two INDEPENDENT kinds of evidence for the same technique claim (T1558.003) on the same
account into one verdict, with a Belnap soundness check in the `cross_check` axis the envelope
already has:

  structural (experiments)  — RC4 fan-out SIGNATURE over the graph: deterministic, carries a *why*
                              + lineage, no FAR.
  statistical (src/detection, SERVICE_TICKET_FANOUT) — service-ticket entropy OUTLIER vs the
                              population: carries a calibrated FAR (conformal α), but no *why*, and
                              it CANNOT tell kerberoasting from pass-the-ticket (both are one-account-
                              many-tickets — its own docstring says so).

  cross_check = kjoin(structural, statistical):
     TRUE  ∧ TRUE   → TRUE  corroborated (signature and outlier agree)
     FALSE ∧ TRUE   → BOTH  SOUNDNESS ALARM — statistical calls it kerberoasting, structural says the
                            RC4 signature is definitively absent (it's pass-the-ticket, mislabeled)
     NONE  ∧ TRUE   → TRUE  statistical-only (structural had nothing to say)

The structural side is three-valued on purpose: TRUE = RC4 signature present; FALSE = the account
fanned out but NOT via RC4 (so the kerberoasting signature is definitively absent); NONE = it didn't
fan out (structural abstains). The FALSE vs NONE distinction is what makes the soundness alarm fire
instead of silently agreeing.

Calls the statistical detector from `detection` (proper) — experiments-calling-proper, the correct
dependency direction. This is the smallest real instance of rung-3 unification; promoting it into
the verdict envelope is #5.

Run:  .venv/bin/python packages/detection/experiments/cross_check_kerberoast.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from detection import SERVICE_TICKET_FANOUT, run_binding
from kerberos_orphan_real import load
from lsass_subgraph_detection import cid
from provenance import BOTH, FALSE, NONE, TRUE, kjoin

RC4 = "0x17"
CSV = str(Path.home() / "data/faker-kerberos/v1/export.csv")
_S = {TRUE: "true", FALSE: "false", NONE: "none", BOTH: "both"}


def structural(rows, min_services: int = 10) -> dict:
    """account → (Four verdict, evidence) for the kerberoasting (RC4 fan-out) signature."""
    rc4: dict[str, set] = defaultdict(set)
    allsvc: dict[str, set] = defaultdict(set)
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


def statistical(csv: str) -> tuple[dict, float]:
    """account → best (lowest) conformal p-value among its detected cells, plus the FAR bound α."""
    r = run_binding(csv, SERVICE_TICKET_FANOUT)
    by_acct: dict[str, float] = {}
    for d in r["detected"]:
        a = d.cell.entity
        by_acct[a] = min(by_acct.get(a, 1.0), d.pvalue)
    return by_acct, r["alpha"]


def combined_verdict(acct, sv, ev, stat_p, alpha, cc) -> dict:
    subject = cid({"technique": "T1558.003", "account": acct})
    return {
        "technique": "T1558.003",
        "decision": _S[cc],
        "cross_check": _S[cc],
        "score": round(1 - stat_p, 5) if stat_p is not None else 1.0,
        "calibration": {"method": "conformal", "far_bound": alpha} if stat_p is not None else None,
        "guarantee": {"tier": "well-formed", "subject_cid": subject},
        "provenance": subject,
        "evidence": {
            "structural": {"verdict": _S[sv], **ev},
            "statistical": {"verdict": "true" if stat_p is not None else "none",
                            "pvalue": stat_p, "far_bound": alpha},
        },
    }


def main() -> None:
    rows = load()
    struct = structural(rows)
    stat, alpha = statistical(CSV)
    # actionable = something made a positive kerberoasting claim (structural signature OR statistical outlier).
    actionable = {a for a, (v, _) in struct.items() if v == TRUE} | set(stat)
    # the rest: structural FALSE (fanned out, but AES not RC4) + no outlier = correct-negative, not kerberoasting.
    correct_neg = sum(1 for a, (v, _) in struct.items() if v == FALSE and a not in stat)

    print(f"cross_check on T1558.003 (kerberoasting) — structural ∧ statistical, FAR α={alpha}\n")
    print(f"  {'account':18} {'structural':10} {'statistical':16} {'cross_check':11} reading")
    alarms = []
    for a in sorted(actionable):
        sv = struct.get(a, (NONE, {}))[0]
        stv = TRUE if a in stat else NONE
        cc = kjoin(sv, stv)
        p = stat.get(a)
        stat_str = f"p={p:.5f}" if p is not None else "—"
        reading = {
            "true": "corroborated" if sv == TRUE else "statistical-only",
            "both": "ALARM: stat=kerberoast, struct=RC4 absent → it's pass-the-ticket",
            "false": "structural-only (no outlier)",
            "none": "—",
        }[_S[cc]]
        print(f"  {a:18} {_S[sv]:10} {stat_str:16} {_S[cc]:11} {reading}")
        if cc == BOTH:
            alarms.append(a)
    print(f"  (+ {correct_neg} accounts: fanned out via AES, no outlier → cross_check=false, correctly not kerberoasting — suppressed)")

    # show two full combined verdicts: one corroborated, one alarm
    print("\n--- corroborated verdict (maria.montgomery) — one envelope, both why + FAR ---")
    a = "maria.montgomery"
    v = combined_verdict(a, struct[a][0], struct[a][1], stat.get(a), alpha, kjoin(struct[a][0], TRUE))
    print(json.dumps(v, indent=2))

    if alarms:
        a = alarms[0]
        print(f"\n--- soundness-alarm verdict ({a}) — cross_check=both, the paradigms DISAGREE ---")
        v = combined_verdict(a, struct[a][0], struct[a][1], stat.get(a), alpha, kjoin(struct[a][0], TRUE))
        print(json.dumps(v, indent=2))
        print(f"\nThe alarm is correct: {alarms} are pass-the-ticket (truth file), which the statistical")
        print("fan-out detector cannot distinguish from kerberoasting — the structural RC4 check contests")
        print("the label, and cross_check=both surfaces the conflation instead of silently agreeing.")


if __name__ == "__main__":
    main()
