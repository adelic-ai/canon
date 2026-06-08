"""First cell on real ATT&CK-labeled OTRF/Mordor data — the honest finding is about RULE-COVERAGE
COMPOSITION, not a Sigma blind spot. The named technique IS covered by SigmaHQ; whether a deployment
catches it depends on WHICH rules it runs, and canon's value is measuring that against the mechanism.

Dataset: OTRF/Security-Datasets compound/LSASS_campaign_03 (single-host, 41,954 events; the attack is
metasploit_comsvcs_lsass_memory_dump -> T1003.001 credential dumping). Staged at
``~/data/otrf-security-datasets/LSASS_campaign_03/``.

The detectors, and what each catches of the 3 processes that READ lsass memory
(winx64_payload [the metasploit payload], rundll32 [the comsvcs MiniDump LOLBin], wmiprvse):

  1) BOTTOM-UP battery (fan-out / per-entity anomaly): blind to low-volume content. rundll32 fired ONE
     access event -> statistically invisible (ranked #12 of 26). MISSES rundll32.
  2a) GENERIC Sigma rule (proc_access_win_lsass_susp_access_flag, the GrantedAccess-flag rule): its
     filter ALLOWLISTS all of system32 to cut FPs. rundll32 lives in system32 -> allowlisted away.
     MISSES rundll32. This is ONE rule, not "Sigma".
  2b) DEDICATED Sigma rule (proc_access_win_lsass_dump_comsvcs_dll): SourceImage=rundll32 AND
     TargetImage=lsass AND CallTrace contains comsvcs.dll. The data's CallTrace HAS comsvcs.dll, so
     this rule CATCHES rundll32. SigmaHQ is NOT blind to this technique.
  3) EXACT MECHANISM (canon fidelity check): TargetImage=lsass AND GrantedAccess & PROCESS_VM_READ,
     no path trust. Catches ALL 3 reads, including rundll32.
  4) DEFAULT-DENY allowlist (positive model, keyed on legit-reader identity): catches all non-legit.

Finding (corrected 2026-06-07): the technique is NOT a Sigma blind spot — a dedicated rule (2b) catches
it on this exact telemetry. The real variable is rule-COVERAGE: a deployment running only the generic
flag-rule (2a) has a blind spot the dedicated rule (2b) closes. Canon's value is measuring a deployment's
ACTUAL rule set against the mechanism (3) and surfacing which rules are load-bearing — not "we catch what
Sigma misses." Earlier versions of this cell over-claimed "off-the-shelf Sigma misses it" by testing only
rule 2a and never parsing CallTrace; that was wrong and is fixed here.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from detection._verdict import emit_detection_verdict
from provenance import TRUE

DATA = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
PROCESS_VM_READ = 0x10
# the retrieved Sigma rule's SourceImage allowlist, faithfully (path-based filters that bite on this data)
_ALLOW_PREFIX = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                 "c:\\program files\\", "c:\\program files (x86)\\")
_ALLOW_EXACT = {"c:\\windows\\system32\\wbem\\wmiprvse.exe"}  # filter1 explicit

# detector 4: the POSITIVE (default-deny) model — the closed set of process images that
# legitimately read lsass memory. Everything else is a policy violation by construction.
# This is the detective shadow of LSA Protection (RunAsPPL) / Credential Guard: the control
# that *should* be native to lsass, recovered from telemetry for when it's off or bypassed.
# Keyed on the legit-reader IDENTITY, NOT on a trusted path (the bug that let rundll32 through).
# Illustrative; a real deployment calibrates this set per-environment (EDR agent, etc.).
# Note: wmiprvse is deliberately ABSENT — the Sigma rule path-trusts it; a strict default-deny
# routes it to review rather than silently trusting it (NONE/adjudicate, not False).
_LEGIT_LSASS_READERS = frozenset({
    "lsass.exe", "wininit.exe", "csrss.exe", "services.exe",  # core Windows logon/session
    "msmpeng.exe",                                            # Microsoft Defender
})


def _lsass_reads(events: list[dict]) -> list[tuple[str, str, str]]:
    """(full SourceImage, mask, CallTrace) for every ProcessAccess that READS lsass memory (mask & VM_READ)."""
    out = []
    for e in events:
        if str(e.get("EventID")) != "10" or "lsass.exe" not in str(e.get("TargetImage", "")).lower():
            continue
        m = str(e.get("GrantedAccess", "0x0"))
        try:
            if int(m, 16) & PROCESS_VM_READ:
                out.append((str(e.get("SourceImage", "")), m, str(e.get("CallTrace", ""))))
        except ValueError:
            pass
    return out


def _sigma_generic_allowlisted(src: str) -> bool:
    """Rule 2a (generic GrantedAccess-flag rule): is this SourceImage allowlisted (filter_generic + filter1)?"""
    low = src.lower()
    return low in _ALLOW_EXACT or low.startswith(_ALLOW_PREFIX)


def _sigma_dedicated_comsvcs(src: str, calltrace: str) -> bool:
    """Rule 2b (proc_access_win_lsass_dump_comsvcs_dll, SigmaHQ master): rundll32 -> lsass with
    comsvcs.dll in the CallTrace. Verified against the live SigmaHQ rule logic, not transcribed loosely."""
    return src.lower().endswith("\\rundll32.exe") and "comsvcs.dll" in calltrace.lower()


def main() -> None:
    events = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]
    by_proc = {}            # basename -> full SourceImage
    comsvcs_callers = set()  # basenames whose reads carry comsvcs.dll in the CallTrace (rule 2b)
    for src, m, ct in _lsass_reads(events):
        name = src.split("\\")[-1]
        by_proc.setdefault(name, src)
        if _sigma_dedicated_comsvcs(src, ct):
            comsvcs_callers.add(name)

    print(f"processes that READ lsass memory (exact mechanism, GrantedAccess & 0x10): {sorted(by_proc)}\n")

    # detector 2a: generic GrantedAccess-flag Sigma rule (selection AND NOT system32 allowlist)
    sigma_generic = sorted(name for name, full in by_proc.items() if not _sigma_generic_allowlisted(full))
    # detector 2b: DEDICATED comsvcs Sigma rule (CallTrace contains comsvcs.dll)
    sigma_dedicated = sorted(comsvcs_callers)
    # detector 3: the exact mechanism (no path trust)
    mech_flags = sorted(by_proc)
    # detector 4: positive (default-deny) model — flag any reader NOT in the legit-reader set
    deny_flags = sorted(name for name in by_proc if name.lower() not in _LEGIT_LSASS_READERS)

    print("DETECTOR COMPARISON on the lsass-memory reads:")
    print(f"  1)  bottom-up battery          : MISSES rundll32 (1 event, ranked #12/26 — statistically invisible)")
    print(f"  2a) generic Sigma flag-rule    : flags {sigma_generic}")
    for name, full in sorted(by_proc.items()):
        if _sigma_generic_allowlisted(full):
            print(f"        allowlisted away: {name}  ({full})")
    print(f"  2b) DEDICATED comsvcs rule     : flags {sigma_dedicated}  (CallTrace has comsvcs.dll — CATCHES rundll32)")
    print(f"  3)  EXACT mechanism (canon)    : flags {mech_flags}")
    print(f"  4)  default-deny allowlist     : flags {deny_flags}  (reader NOT in legit set; path-agnostic)")

    print(f"\nCORRECTED FINDING: the technique is NOT a Sigma blind spot — the dedicated rule 2b catches rundll32")
    print(f"  on this exact telemetry (CallTrace carries comsvcs.dll). The real variable is rule COVERAGE:")
    missed_by_generic = sorted(set(mech_flags) - set(sigma_generic))
    print(f"  -> a deployment running ONLY the generic flag-rule (2a) misses {missed_by_generic} (system32 allowlist);")
    print(f"     adding the dedicated rule (2b) closes the rundll32/comsvcs gap. Coverage composition, not a defect.")
    print(f"  -> canon's value: measure a deployment's ACTUAL rule set against the mechanism (3) and surface which")
    print(f"     rules are load-bearing — NOT 'we catch what Sigma misses' (false; a dedicated Sigma rule catches it).")

    caught_by_deny = sorted(set(deny_flags) & set(missed_by_generic))
    print(f"\nDEFAULT-DENY (preventive-control shadow): keyed on legit-reader IDENTITY (not path), it catches {caught_by_deny}")
    print(f"  that the generic flag-rule's 'trust system32' breadth misses — rundll32 is simply NOT a legit lsass reader.")
    print(f"  (Here detector 4 == detector 3 only because NO legit reader appears in-window. Their real difference:")
    print(f"   default-deny = mechanism + FP control keyed on legit-reader IDENTITY — it would clear Defender/wininit")
    print(f"   reads that raw mechanism flags, while still catching a LOLBin a path-keyed allowlist trusts away.)")
    print(f"  This is the detective shadow of LSA Protection (RunAsPPL) / Credential Guard — the OS-native default-deny")
    print(f"  on lsass reads — recovered from telemetry for when that preventive control is off or BYOVD-bypassed.")

    # justified verdict for a mechanism-confirmed read, recording the rule-coverage state
    target = "rundll32.exe"
    full = by_proc[target]
    verdict = emit_detection_verdict(
        f"LSASS_campaign_03|{target}|vm_read_lsass",
        technique="T1003.001",   # mechanistic: VM_READ-to-lsass IS LSASS-memory credential dumping
        pvalue=1e-3,              # NOMINAL placeholder — a deterministic signature has NO natural Pfa;
                                  # the LLR-confidence fold assumes a statistical detector (an honest mismatch)
        params={"mechanism": "EventID10 TargetImage=lsass GrantedAccess&0x10",
                "source": full,
                "rule_coverage": "dedicated Sigma proc_access_win_lsass_dump_comsvcs_dll CATCHES this "
                                 "(CallTrace has comsvcs.dll); generic flag-rule MISSES it (system32 allowlist); "
                                 "battery MISSES it (low-volume) -- coverage depends on which rules run"},
        what=TRUE,                # the memory read occurred (observed in telemetry)
        calibration=None,         # honest: no FAR; deterministic mechanism, single dataset
    )
    print("\n=== JUSTIFIED VERDICT (mechanism-confirmed, records the rule-coverage state) ===")
    print(f"  technique:   {verdict.technique}   decision: {verdict.decision}")
    print(f"  guarantee:   tier {verdict.guarantee.tier} (well_formed)   custody: {verdict.custody} (unsigned)")
    print(f"  calibration: {verdict.calibration} (honest — deterministic mechanism, FAR unmeasured)")
    print(f"  provenance:  {str(verdict.provenance)[:40]}...")

    print("\n=== what this cell shows (honest scope) ===")
    print("  PROVEN end-to-end: real OTRF data -> detectors -> justified verdict; and that canon's value")
    print("    is measuring rule COVERAGE against the mechanism — a deployment running only the generic")
    print("    flag-rule has a blind spot the dedicated comsvcs rule closes. The technique is NOT a Sigma")
    print("    blind spot (a dedicated rule catches it); the risk is which rules a deployment actually runs.")
    print("    The default-deny allowlist (detector 4) is the preventive-control shadow (LSA Protection /")
    print("    Credential Guard), independent of the rule-coverage point.")
    print("    NOT shown: calibrated FAR, generalization (one host, one dataset); the legit-reader set is")
    print("    illustrative (real deployments calibrate it per-environment); the Sigma rules are transcribed")
    print("    here (a real version executes them via pySigma and diffs against the mechanism automatically).")


if __name__ == "__main__":
    main()
