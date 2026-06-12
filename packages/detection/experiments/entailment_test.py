"""The abduction loop's TEST step, on real data: an anchor motif ENTAILS a
dependent motif, so the system goes looking for it — and a missing-but-entailed
motif becomes evidence, not silence.

This is the dependency mechanism from web/completeness_channel.html and the
abduction loop (web/abduction_loop.html), made executable on top of the
subgraph matcher:

  A comsvcs MiniDump SPAWN (EID1) ENTAILS a VM_READ to lsass (EID10) — you cannot
  dump credentials without reading lsass memory. So given the spawn, the read is
  EXPECTED. Its presence/absence is then meaningful three ways:

    CONFIRMED  the expected motif is present                      -> read grounds TRUE
    GAP        absent, but EID10 IS collected                     -> the read is ENTAILED
               (so it happened — abduced from the spawn), yet its    (= a telemetry gap:
               record is missing                                     collection-fail / evasion)
    NONE       absent, and EID10 is NOT collected                 -> unobservable, no claim

The load-bearing point: because the spawn ENTAILS the read, "it didn't happen" is
ruled out in the GAP case — the absence is promoted from silent to evidence, and
the cause narrows from {organic / fail / evasion} to {fail / evasion}.

Demonstrated by replaying the SAME anchor against three corpora (full / the read
record withheld / EID10 channel withheld).

Run:  .venv/bin/python packages/detection/experiments/entailment_test.py
"""

from __future__ import annotations

from dataclasses import dataclass

from lsass_subgraph_detection import PROCESS_VM_READ, basename, cid, load
from subgraph_matcher import LSASS_DUMP, MotifSpec, _instances, granted_has


@dataclass(frozen=True)
class Entailment:
    """anchor present  ⊢  expect (rationale).  The forward-progression edge."""
    rationale: str
    anchor: MotifSpec
    expected: MotifSpec


# reuse the exact motifs the matcher already defines (spawn anchors, lsass_read expected)
SPAWN_ENTAILS_READ = Entailment(
    rationale="a comsvcs MiniDump spawn cannot dump credentials without a VM_READ to lsass",
    anchor=LSASS_DUMP.motifs[0],     # EID1 comsvcs spawn, joins on ProcessGuid
    expected=LSASS_DUMP.motifs[1],   # EID10 lsass VM_READ, joins on SourceProcessGUID
)


def run_test(ent: Entailment, events: list[dict]) -> tuple[list[dict], bool]:
    """For each anchor, look for the entailed motif joined at the same node and
    classify the outcome against observability (is the expected EID collected?)."""
    anchors = _instances(events, ent.anchor)
    expected_collected = any(str(e.get("EventID")) == ent.expected.eid for e in events)
    findings = []
    for jv, anchor_evs in anchors.items():
        hits = [e for e in events
                if str(e.get("EventID")) == ent.expected.eid
                and e.get(ent.expected.join_field) == jv
                and ent.expected.pred(e)]
        if hits:
            outcome, carrier = "CONFIRMED", "true"
        elif expected_collected:
            outcome, carrier = "GAP", "gap"      # entailed + absent + collected
        else:
            outcome, carrier = "NONE", "none"    # unobservable
        findings.append({
            "join": jv,
            "anchor_cid": cid(anchor_evs[0]),
            "expected_cids": [cid(h) for h in hits],
            "outcome": outcome,
            "carrier": carrier,
        })
    return findings, expected_collected


def _report(label: str, ent: Entailment, events: list[dict]) -> None:
    findings, collected = run_test(ent, events)
    print(f"--- {label}  (EID10 collected: {collected}) ---")
    for f in findings:
        line = f"  anchor {f['anchor_cid']}  ->  expect lsass-read  ->  {f['outcome']} (carrier={f['carrier']})"
        print(line)
        if f["outcome"] == "CONFIRMED":
            print(f"      read grounded at {f['expected_cids'][0]}")
        elif f["outcome"] == "GAP":
            print("      ENTAILED but record absent while EID10 IS collected:")
            print("      the read happened (abduced from the spawn) -> telemetry gap (collection-fail")
            print("      or anti-forensic deletion). 'It didn't happen' is RULED OUT by the entailment.")
        else:
            print("      absent AND EID10 uncollected -> unobservable; NOT a clean bill, no claim.")
    print()


def main() -> None:
    events = load()
    ent = SPAWN_ENTAILS_READ
    print(f"entailment: {ent.rationale}\n")

    # 1. full corpus — the expected read is present -> CONFIRMED (forward-progression worked)
    _report("1. full corpus", ent, events)

    # 2. withhold the read RECORD for this process, but keep the EID10 channel intact.
    #    The read still happened; we just don't have its event. -> GAP (collected-but-absent).
    anchor_guids = set(_instances(events, ent.anchor).keys())
    minus_record = [e for e in events
                    if not (str(e.get("EventID")) == "10"
                            and e.get("SourceProcessGUID") in anchor_guids
                            and "lsass" in str(e.get("TargetImage", "")).lower())]
    _report("2. read record withheld (EID10 channel still collected)", ent, minus_record)

    # 3. withhold the EID10 channel entirely -> unobservable -> NONE
    minus_channel = [e for e in events if str(e.get("EventID")) != "10"]
    _report("3. EID10 channel withheld entirely (uncollected)", ent, minus_channel)

    print("Same anchor, three corpora -> CONFIRMED / GAP / NONE. The entailment is what makes")
    print("the absence legible: a missing-but-entailed motif is the structural gap frontier the")
    print("abduction loop's TEST step points the next check at.")


if __name__ == "__main__":
    main()
