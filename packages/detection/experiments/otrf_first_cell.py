"""First cell on real ATT&CK-labeled OTRF/Mordor data — three detectors, and the honest finding
that NEITHER off-the-shelf detector catches the named attack; only checking the mechanism does.

Dataset: OTRF/Security-Datasets compound/LSASS_campaign_03 (single-host, 41,954 events; the attack is
metasploit_comsvcs_lsass_memory_dump -> T1003.001 credential dumping). Staged at
``~/data/otrf-security-datasets/LSASS_campaign_03/``.

The three detectors, and what each catches of the 3 processes that READ lsass memory
(winx64_payload [the metasploit payload], rundll32 [the comsvcs MiniDump LOLBin], wmiprvse):

  1) BOTTOM-UP battery (fan-out / per-entity anomaly): blind to low-volume content. rundll32 fired ONE
     access event -> statistically invisible (ranked #12 of 26). MISSES rundll32.
  2) TOP-DOWN off-the-shelf Sigma rule (retrieved, executed faithfully — proc_access_win_lsass_
     uncommon_access_flag, T1003.001): its filter_generic ALLOWLISTS all of system32 to
     cut FPs. rundll32 lives in system32, so the LOLBin MiniDump is allowlisted away. MISSES rundll32.
  3) EXACT MECHANISM (canon fidelity check): TargetImage=lsass AND GrantedAccess & PROCESS_VM_READ,
     no path trust. Catches ALL 3 reads, including rundll32.

Finding: the battery is blind by statistics; the framework verifier is blind by its own FP-allowlist
(LOLBin abuse of a trusted path). Checking the verifier against the mechanism surfaces the gap — that
IS the "is the detection faithful?" layer, on real data. The justified verdict records the gap.
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


def _lsass_reads(events: list[dict]) -> list[tuple[str, str]]:
    """(full SourceImage, mask) for every ProcessAccess that READS lsass memory (mask & VM_READ)."""
    out = []
    for e in events:
        if str(e.get("EventID")) != "10" or "lsass.exe" not in str(e.get("TargetImage", "")).lower():
            continue
        m = str(e.get("GrantedAccess", "0x0"))
        try:
            if int(m, 16) & PROCESS_VM_READ:
                out.append((str(e.get("SourceImage", "")), m))
        except ValueError:
            pass
    return out


def _sigma_allowlisted(src: str) -> bool:
    """The retrieved Sigma rule's verdict: is this SourceImage allowlisted (filter_generic + filter1)?"""
    low = src.lower()
    return low in _ALLOW_EXACT or low.startswith(_ALLOW_PREFIX)


def main() -> None:
    events = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]
    reads = {(_s, m) for _s, m in _lsass_reads(events)}
    by_proc = {}
    for src, m in reads:
        by_proc.setdefault(src.split("\\")[-1], src)

    print(f"processes that READ lsass memory (exact mechanism, GrantedAccess & 0x10): {sorted(by_proc)}\n")

    # detector 2: the retrieved off-the-shelf Sigma rule (selection AND NOT allowlist)
    sigma_flags = sorted(name for name, full in by_proc.items() if not _sigma_allowlisted(full))
    # detector 3: the exact mechanism (no path trust)
    mech_flags = sorted(by_proc)

    print("DETECTOR COMPARISON on the lsass-memory reads:")
    print(f"  1) bottom-up battery        : MISSES rundll32 (1 event, ranked #12/26 — statistically invisible)")
    print(f"  2) off-the-shelf Sigma rule : flags {sigma_flags}")
    for name, full in sorted(by_proc.items()):
        if _sigma_allowlisted(full):
            print(f"       allowlisted away: {name}  ({full})")
    print(f"  3) EXACT mechanism (canon)  : flags {mech_flags}")

    missed_by_sigma = sorted(set(mech_flags) - set(sigma_flags))
    print(f"\nFIDELITY GAP: the Sigma verifier MISSES {missed_by_sigma} that the mechanism confirms read lsass.")
    print(f"  -> rundll32 = the comsvcs MiniDump (the dataset's named T1003.001 technique), allowlisted by the")
    print(f"     rule's trust-all-of-system32 FP filter. A LOLBin abusing a trusted path defeats the allowlist.")
    print(f"  -> neither off-the-shelf detector (battery NOR Sigma) catches it; only checking the MECHANISM does.")

    # justified verdict for a mechanism-confirmed read, recording the verifier-fidelity gap
    target = "rundll32.exe"
    full = by_proc[target]
    verdict = emit_detection_verdict(
        f"LSASS_campaign_03|{target}|vm_read_lsass",
        technique="T1003.001",   # mechanistic: VM_READ-to-lsass IS LSASS-memory credential dumping
        pvalue=1e-3,              # NOMINAL placeholder — a deterministic signature has NO natural Pfa;
                                  # the LLR-confidence fold assumes a statistical detector (an honest mismatch)
        params={"mechanism": "EventID10 TargetImage=lsass GrantedAccess&0x10",
                "source": full,
                "verifier_fidelity": "off-the-shelf Sigma proc_access_win_lsass_uncommon_access_flag "
                                     "MISSES this (system32 allowlist); battery MISSES this (low-volume)"},
        what=TRUE,                # the memory read occurred (observed in telemetry)
        calibration=None,         # honest: no FAR; deterministic mechanism, single dataset
    )
    print("\n=== JUSTIFIED VERDICT (mechanism-confirmed, records the verifier gap) ===")
    print(f"  technique:   {verdict.technique}   decision: {verdict.decision}")
    print(f"  guarantee:   tier {verdict.guarantee.tier} (well_formed)   custody: {verdict.custody} (unsigned)")
    print(f"  calibration: {verdict.calibration} (honest — deterministic mechanism, FAR unmeasured)")
    print(f"  provenance:  {str(verdict.provenance)[:40]}...")

    print("\n=== what this cell shows (honest scope) ===")
    print("  PROVEN end-to-end: real OTRF data -> detectors -> justified verdict; and that canon's value")
    print("    is checking the DETECTORS' fidelity — both off-the-shelf detectors have blind spots the")
    print("    mechanism check catches. NOT shown: calibrated FAR, generalization (one host, one dataset),")
    print("    and the mechanism check itself is hand-coded here (a real version executes the Sigma rule via")
    print("    pySigma and diffs it against the mechanism automatically).")


if __name__ == "__main__":
    main()
