"""Cross-check — pair an independent STRUCTURAL signature with the STATISTICAL fan-out detector so the
verdict's ``cross_check`` axis is a genuine *cross-paradigm* soundness check.

``fanout``'s own cross-check uses a *within-paradigm* measure (distinct-count vs entropy) that is
correlated with the primary, so its docstring flags a disagreement as a deferred claim. This one pairs
two **independent mechanisms** — a deterministic structural signature vs the conformal outlier — so a
disagreement is operationally meaningful. A fan-out is technique-BLIND ("one account, many service
tickets" is kerberoasting *and* pass-the-ticket); the structural signature says *which* technique, and
``cross_check = both`` surfaces the conflation instead of burying it.

    cross_check = kjoin(statistical_decision = TRUE, structural_verdict):
        structural TRUE  -> TRUE   corroborated (signature and outlier agree)
        structural FALSE -> BOTH   soundness alarm (fan-out present, but NOT this signature)
        structural NONE  -> TRUE   statistical-only (structural abstains)

Structural verdicts are THREE-valued on purpose: FALSE (fanned out but definitively not this
signature) is distinct from NONE (did not fan out) — that distinction is what makes the alarm fire.

The structural signatures are the relational/structural paradigm promoted from experiments; the
statistical side reuses the existing :mod:`detection.fanout` bindings. Validated in
``tests/test_cross_check.py`` against the faker-kerberos truth file.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from collections.abc import Callable

from forge_core import Calibration, DetectionVerdict
from provenance import FALSE, NONE, TRUE, Four

from detection._verdict import emit_detection_verdict
from detection.fanout import FanoutBinding, run_binding

RC4 = "0x17"          # Ticket_Encryption_Type for RC4-HMAC (the crackable/downgrade encryption)
_FAIL = "0x18"        # pre-auth failed / bad password


def load_kerberos_rows(path: str) -> list[dict]:
    """Full Kerberos CSV rows — the structural signatures need Ticket_Encryption_Type / Ticket_Hash,
    richer than the ``(seconds, entity, value)`` tuples :func:`detection.fanout.load_kerberos_events`
    projects."""
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _ip(s: str) -> str:
    return s.replace("::ffff:", "")


def kerberoast_signature(rows: list[dict], min_services: int = 10) -> dict[str, Four]:
    """RC4 fan-out: TRUE = >=min distinct RC4 service tickets; FALSE = fanned out but not via RC4;
    NONE = did not fan out."""
    rc4, allsvc = defaultdict(set), defaultdict(set)
    for r in rows:
        if r.get("EventCode") == "4769":
            allsvc[r["Account_Name"]].add(r.get("Service_Name", ""))
            if r.get("Ticket_Encryption_Type") == RC4:
                rc4[r["Account_Name"]].add(r.get("Service_Name", ""))
    return {a: (TRUE if len(rc4[a]) >= min_services
                else FALSE if len(allsvc[a]) >= min_services else NONE) for a in allsvc}


def ptt_signature(rows: list[dict], min_orphan: int = 3, fanout_floor: int = 10) -> dict[str, Four]:
    """Orphan-TGT fan-out: TRUE = an orphan TGT (no issuing 4768) fanning >=min_orphan services;
    FALSE = fanned out (>=fanout_floor) on a legit TGT; NONE = did not fan out."""
    issued = {r["Ticket_Hash"] for r in rows if r.get("EventCode") == "4768" and r.get("Ticket_Hash")}
    orphan, allsvc = defaultdict(set), defaultdict(set)
    for r in rows:
        if r.get("EventCode") == "4769":
            a = r["Account_Name"]
            allsvc[a].add(r.get("Service_Name", ""))
            if r.get("Ticket_Hash") and r["Ticket_Hash"] not in issued:
                orphan[a].add(r.get("Service_Name", ""))
    return {a: (TRUE if len(orphan[a]) >= min_orphan
                else FALSE if len(allsvc[a]) >= fanout_floor else NONE) for a in allsvc}


def spray_signature(rows: list[dict], min_accounts: int = 10) -> dict[str, Four]:
    """Source-IP spray: TRUE = >=min_accounts distinct accounts FAILED auth from this IP;
    FALSE = touched >=min_accounts accounts but without the failure pattern; NONE = few accounts."""
    fail, allacct = defaultdict(set), defaultdict(set)
    for r in rows:
        ip = _ip(r.get("Client_Address", ""))
        if not ip:
            continue
        allacct[ip].add(r.get("Account_Name", ""))
        if r.get("Failure_Code") == _FAIL or r.get("Status") == _FAIL:
            fail[ip].add(r.get("Account_Name", ""))
    return {ip: (TRUE if len(fail[ip]) >= min_accounts
                 else FALSE if len(allacct[ip]) >= min_accounts else NONE) for ip in allacct}


def cross_check_verdicts(
    path: str,
    *,
    binding: FanoutBinding,
    signature: Callable[[list[dict]], dict[str, Four]],
    technique: str | None = None,
) -> list[DetectionVerdict]:
    """For each entity the statistical ``binding`` flags, emit a :class:`~forge_core.DetectionVerdict`
    whose ``check`` is the independent structural ``signature`` verdict, so the verdict's
    ``cross_check`` = kjoin(detect, signature). One verdict per entity (best/lowest p-value cell)."""
    technique = technique or binding.technique
    sig = signature(load_kerberos_rows(path))
    best: dict[str, object] = {}
    for d in run_binding(path, binding)["detected"]:
        e = _ip(d.cell.entity)
        if e not in best or d.pvalue < best[e].pvalue:
            best[e] = d
    out = []
    for entity, d in best.items():
        out.append(emit_detection_verdict(
            f"{binding.name}|{entity}",
            technique=technique,
            pvalue=d.pvalue,
            params={"entity": entity, "binding": binding.name, "structural": str(sig.get(entity, NONE))},
            check=sig.get(entity, NONE),                 # independent structural measure -> cross_check
            calibration=Calibration("conformal", binding.alpha),
            when=NONE,
        ))
    return out
