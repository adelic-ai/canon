"""Entity+window cross-model corroboration — join a behavioral detector to external rules at the grain
where they actually meet: the same actor, the same window, across telemetry models.

The single-event panel (:func:`detection.cross_check.sigma_corroborator`) scores one triggering event.
But a behavioral detector (the 4769 RC4 ticket fan-out — Kerberoasting, tool-agnostic) and a tool-artifact
rule (Rubeus registering its logon provider, EID 4611) read *different events*; scoring one against the
other's rule is the wrong grain and always misses. They corroborate only when you take the flagged actor's
**full multi-EID stream in the flagged window** and run the deduped Sigma panel over all of it.

Kerberoasting is a TECHNIQUE, not a tool. The 4769 RC4 fan-out is intrinsic (every tool leaves it); the
Rubeus 4611 artifact is incidental (Rubeus only). So this join treats Rubeus as ONE witness among
possibly several, never the definition:

    Rubeus actor     fan-out fires → panel over the window fires BOTH win_security_kerberoasting_activity
                     (behavioral, 4769 RC4) AND ...register_new_logon_process_by_rubeus (4611) → two
                     independent witnesses corroborate (the technique happened; it was Rubeus).
    non-Rubeus actor fan-out fires → panel fires the behavioral rule only; the Rubeus artifact is ABSENT
    (Impacket, etc.) → corroboration is NONE for the tool, never FALSE (absence ≠ refutation).

The corroboration lands as a PROVENANCE EDGE on the verdict (via :func:`~detection._verdict.emit_detection_verdict`),
the same content-addressed home as the single-event panel. Constructive existence-proof on a
mechanism-modelled corpus (the :func:`synthesize_kerberoast_corpus` generator), with a built-in negative
control (the non-Rubeus actor); real-data validation is DEFERRED for want of a corpus carrying both traces.
"""

from __future__ import annotations

from forge_core import Calibration, DetectionVerdict, conformal_pvalues  # noqa: F401  (re-export parity)
from provenance import TRUE

from detection._verdict import emit_detection_verdict
from detection.fanout import detect_fanout
from detection.sigma_panel import corroborate

RC4 = "0x17"  # TicketEncryptionType for RC4-HMAC — the crackable encryption Kerberoasting forces
SECURITY = {"product": "windows", "service": "security"}


def slice_entity_window(events: list[dict], entity: str, t0: float, t1: float,
                        *, entity_field: str, time_field: str) -> list[dict]:
    """The flagged actor's full multi-EID event stream within ``[t0, t1)`` — the grain at which a
    behavioral finding and a tool-artifact rule can corroborate."""
    return [e for e in events if e.get(entity_field) == entity and t0 <= e.get(time_field, -1) < t1]


def cross_model_kerberoast(events: list[dict], *, grain_seconds: float = 3600.0, alpha: float = 0.01,
                           entity_field: str = "Account_Name", value_field: str = "ServiceName",
                           time_field: str = "_sec") -> list[DetectionVerdict]:
    """Behavioral 4769 RC4 ticket fan-out (T1558.003) + entity/window Sigma corroboration.

    For each account the fan-out flags (an account sweeping many distinct RC4 service tickets in a window),
    take that account's FULL event stream in the window and run the deduped windows/security Sigma panel
    over it. Firing rule-classes — behavioral (4769 RC4) and/or tool-artifact (Rubeus 4611) — are recorded
    as a provenance edge on the verdict. A non-Rubeus kerberoast still flags and is corroborated by the
    behavioral rule, with the Rubeus artifact honestly absent."""
    tgs = [(e[time_field], e[entity_field], e.get(value_field, "-"))
           for e in events if str(e.get("EventID")) == "4769" and e.get("TicketEncryptionType") == RC4]
    res = detect_fanout(tgs, grain_seconds=grain_seconds, alpha=alpha)

    out = []
    for d in res["detected"]:
        acct, b = d.cell.entity, d.cell.bin
        t0, t1 = b * grain_seconds, (b + 1) * grain_seconds
        window = slice_entity_window(events, acct, t0, t1, entity_field=entity_field, time_field=time_field)
        corr = corroborate("T1558.003", window, SECURITY)          # panel over the actor's FULL window stream
        corroboration = None
        if corr["votes"] > 0:
            corroboration = {"rules": [name for name, _f, _n in corr["fired"]], "votes": corr["votes"],
                             "classes": corr["classes"], "technique": "T1558.003",
                             "logsource": "windows/security"}
        out.append(emit_detection_verdict(
            f"kerberoast|{acct}|{b}",
            technique="T1558.003",
            pvalue=d.pvalue,
            params={"entity": acct, "bin": b, "window": [t0, t1], "distinct_services": d.cell.distinct},
            who=TRUE, what=TRUE,
            calibration=Calibration("conformal", alpha),
            corroboration=corroboration,
        ))
    return out


def synthesize_kerberoast_corpus(*, n_normal: int = 400, normal_services: int = 3,
                                 attacker_services: int = 18, base: float = 0.0) -> list[dict]:
    """A mechanism-modelled Kerberoasting corpus (NOT a planted detector input): a standing population of
    normal accounts each requesting a few distinct RC4 service tickets, plus two attackers sweeping many
    SPNs — one via Rubeus (also registers the EID-4611 logon provider), one via a non-Rubeus tool (4769
    only, no host artifact). All in one time window. The negative control (non-Rubeus attacker) IS the
    'Kerberoasting without Rubeus' case: it must flag behaviorally and corroborate via the behavioral rule
    while the Rubeus artifact stays absent."""
    events: list[dict] = []

    def tgs(account: str, service: str, t: float) -> dict:
        return {"EventID": "4769", "_sec": t, "Account_Name": account, "ServiceName": service,
                "Status": "0x0", "TicketEncryptionType": RC4}

    # standing population — normal accounts, a few distinct services each (low fan-out)
    for i in range(n_normal):
        acct = f"user{i:03d}"
        for j in range(1 + (i % normal_services)):
            events.append(tgs(acct, f"svc{(i + j) % 40:02d}/host.contoso.com", base + i + j * 0.1))

    # attacker A — Rubeus: sweeps many SPNs AND registers its logon provider (the 4611 tool artifact)
    for k in range(attacker_services):
        events.append(tgs("svc_rubeus", f"MSSQLSvc/db{k:02d}.contoso.com", base + 10 + k * 0.01))
    events.append({"EventID": "4611", "_sec": base + 10, "Account_Name": "svc_rubeus",
                   "LogonProcessName": "User32LogonProcesss"})

    # attacker B — non-Rubeus (e.g. Impacket GetUserSPNs): same behavioral fan-out, NO host artifact
    for k in range(attacker_services):
        events.append(tgs("svc_impacket", f"HTTP/web{k:02d}.contoso.com", base + 20 + k * 0.01))

    return events
