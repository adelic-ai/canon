"""Location coverage — a verdict plus the fidelity-attested detectors at its location.

Realizes `design/verdict_coverage_space.md` against the found labeled multi-detector case (the comsvcs
T1003.001 location in OTRF LSASS_campaign_03). At a labeled location:
  - the **structural detector** is the primary verdict (it stands on its own warrant);
  - rules that fire are **witnesses**, each carrying its *fidelity* (coverage on the corpus) — independent of
    the structural primary (a multi-EID GUID-join vs a single-event field match: different paradigm; FCA-dedup
    is the structural independence pre-filter, measured-MI deferred);
  - applicable rules that **miss** are **gaps**, each with `coverage=false` + a cause — the adjacency map
    ("what does NOT cover this, and why").

**Staged per the wiring contract:** this RECORDS and SHOWS each detector's fidelity at the location; it does
NOT yet collapse them into a weighted score. The contract is honored structurally — the primary stands
regardless (additive); gaps never touch the verdict (absence=`NONE`, recorded not penalized); every
component's fidelity is inspectable (not pre-collapsed). The weighting step waits for a case where it would
change an outcome.
"""

from __future__ import annotations

from dataclasses import dataclass

from forge_core import DetectionVerdict

from detection.cross_check import lsass_dump_corroborated
from detection.fidelity import attest_fidelity
from detection.sigma_eval import evaluate_rule, is_evaluable
from detection.sigma_panel import _logsource, gather
from detection.subgraph import load_sysmon_events

_TECH = "T1003.001"
_LOGSOURCE = "process_access"


@dataclass(frozen=True)
class LocationCoverage:
    """The coverage picture at one labeled location: the primary verdict + the fidelity-attested detectors.

    ``witnesses`` are firing, independent, fidelity-carrying corroborators; ``gaps`` are applicable rules that
    missed, with their coverage + cause (the adjacency map). The verdict stands independent of both."""

    verdict: DetectionVerdict
    technique: str
    witnesses: tuple[dict, ...]   # [{rule, coverage}] — fired, independent of the primary, fidelity-attested
    gaps: tuple[dict, ...]        # [{rule, coverage, cause}] — applicable but missed (what does NOT cover this)


def _comsvcs_positive(events: list[dict]) -> dict | None:
    """The labeled T1003.001 ground-truth instance: the comsvcs rundll32 → lsass EID10 read."""
    spawn = next((e for e in events if str(e.get("EventID")) == "1"
                  and "comsvcs" in str(e.get("CommandLine", "")).lower()), None)
    if spawn is None:
        return None
    return next((e for e in events if str(e.get("EventID")) == "10"
                 and e.get("SourceProcessGUID") == spawn.get("ProcessGuid")
                 and "lsass" in str(e.get("TargetImage", "")).lower()), None)


def lsass_location_coverage(path: str) -> LocationCoverage:
    """The coverage picture at the comsvcs T1003.001 location in an OTRF LSASS corpus: structural primary +
    each applicable Sigma rule's fidelity (witness if it fires, gap with cause if it misses)."""
    events = load_sysmon_events(path)
    positive = _comsvcs_positive(events)
    verdict = lsass_dump_corroborated(path)[0]   # structural primary + its corroboration edge

    witnesses: list[dict] = []
    gaps: list[dict] = []
    for p, r in gather(_TECH):
        if _logsource(r)[0] != _LOGSOURCE or not is_evaluable(r):
            continue
        fires = evaluate_rule(r, positive)["fires"]
        att = attest_fidelity(r, [positive], _TECH, rule_bytes=p.read_bytes(),
                              corpus_id="OTRF/LSASS_campaign_03", corpus_cid="cid:sha256:otrf")
        if fires:
            # independent of the structural primary by construction (multi-EID join vs single-event match)
            witnesses.append({"rule": p.name, "coverage": att["coverage"]})
        else:
            gaps.append({"rule": p.name, "coverage": att["coverage"],
                         "cause": att.get("cause", {}).get("kind", "")})

    return LocationCoverage(verdict=verdict, technique=_TECH,
                            witnesses=tuple(witnesses), gaps=tuple(gaps))
