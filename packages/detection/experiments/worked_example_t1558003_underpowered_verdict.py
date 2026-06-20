"""Worked example — the substrate emitting an HONEST verdict when the population statistic is underpowered.

Companion to ``worked_example_spray_verdict.py``. That one shows a verdict on a *large standing population*
(faker-kerberos) where the conformal fan-out fires and the cross-check *corroborates*. This one runs the
SAME machinery on a real **atomic-red-team** capture (splunk attack_data T1558.003,
``unusual_number_of_kerberos_service_tickets_requested``) — an isolated single-TTP execution with **no benign
background**. There, the population statistic (conformal entropy) is *underpowered* (42 cells, conformal floor
1/(n+1)=0.023 sits ~20× above the standing α=1e-3), so it abstains; only the threshold detector (distinct
count > k), which carries a human prior and needs no population, fires.

The point is not "which detector wins" (a settled, regime-dependent, statistics question — see
``design/cross_check_validation_t1558003_real.md``). The point is that the **substrate reports its own
applicability honestly**: a naive system emits a clean "detected" and hides that the population statistic was
never powered; canon emits a verdict whose conformal arm is an explicit **NONE-with-reason**, whose
cross-check is **uncorroborated** (the redundant measure abstained, not "agree"), whose **calibration is
absent** (the firing detector has no distribution-free bound), and which therefore earns **no `bounded`
claim** — only the well_formed floor. The alert tells you it is a prior-driven flag, not a calibrated one.

Run:  uv run python packages/detection/experiments/worked_example_t1558003_underpowered_verdict.py
(needs ~/data/splunk-attack-data/.../T1558.003/unusual_number_of_kerberos_service_tickets_requested + [rdf]).
"""

import re
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from detection._verdict import build_detection_root, emit_detection_verdict
from detection.fanout import (
    bucket_fanout,
    conformal_pvalues,
    detect_by_distinct_count,
    distinct_value_counts,
    fanout_entropy,
)
from provenance import NONE, TRUE, validate

_DATA = (Path.home() / "data" / "splunk-attack-data" / "datasets" / "attack_techniques" / "T1558.003"
         / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log")
_GRAIN = 600          # 10-min bins, matching the burst timescale
_THRESHOLD = 10       # the distinct-count prior (services-per-account that warrants a look)
_ALPHA = 1e-3         # the standing conformal sweep α (calibrated for large populations)


def _load(path: Path):
    txt = path.read_text(encoding="utf-8", errors="replace")

    def field(ev, name):
        m = re.search(rf"<Data Name='{name}'>(.*?)</Data>", ev)
        return m.group(1) if m else None

    def epoch(ev):
        s = re.search(r"SystemTime='(.*?)'", ev).group(1)[:26].rstrip("Z")
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()

    return [(epoch(ev), field(ev, "TargetUserName"), field(ev, "ServiceName"))
            for ev in re.findall(r"<Event\b.*?</Event>", txt, re.S) if "<EventID>4769</EventID>" in ev]


def main() -> None:
    if not _DATA.exists():
        raise SystemExit(f"corpus absent: {_DATA}")
    events = _load(_DATA)

    # the threshold detector FIRES (no population needed); the conformal detector ABSTAINS (underpowered).
    flagged = detect_by_distinct_count(events, grain_seconds=_GRAIN, threshold=_THRESHOLD)
    cells = fanout_entropy(events, grain_seconds=_GRAIN)
    ent = np.array([c.entropy for c in cells])
    pvals = conformal_pvalues(ent, ent, tail="upper")
    n_cells = len(cells)
    floor = 1.0 / (n_cells + 1)
    conformal_detected = bool((pvals <= _ALPHA).any())

    # the firing entity + its cell (max distinct services), and that cell's conformal p (best the test offers)
    entity = sorted(flagged)[0]
    counts = distinct_value_counts(events, grain_seconds=_GRAIN)
    bins_for = {k: v for k, v in bucket_fanout(events, grain_seconds=_GRAIN).items()}
    (ent_name, ent_bin), distinct = max(((k, c) for k, c in counts.items() if k[0] == entity),
                                        key=lambda kc: kc[1])
    cell_idx = next(i for i, c in enumerate(cells) if c.entity == entity
                    and c.distinct == distinct)
    cell_p = float(pvals[cell_idx])

    # HONEST verdict: detected by the threshold prior; conformal arm abstained (its decision = NONE).
    #   what  = TRUE   — the ∃-detect: distinct-count > k flagged the fan-out
    #   check OMITTED   — the redundant conformal measure ABSTAINED (underpowered). We do NOT pass check=NONE:
    #                    cross_check is kjoin(detect, check) and kjoin(TRUE, NONE)=TRUE would fabricate a
    #                    corroborated-looking TRUE. The axis (a kjoin that absorbs NONE) structurally cannot
    #                    say "attempted but abstained", so we omit it and record the abstention in provenance
    #                    (abstain_reason) + the absent calibration + the no-bounded floor instead.
    #   calibration = None — the firing detector carries no distribution-free FAR bound
    #   exchangeability not passed → no `bounded` claim (can't claim distribution-free when conformal abstained)
    #   track_custody=False → unsigned XML feed, custody/trust PARKED (precondition absent)
    params = {"entity": entity, "bin": ent_bin, "grain_seconds": _GRAIN, "technique": "T1558.003",
              "detector": "distinct_count", "threshold": _THRESHOLD, "distinct": distinct,
              "conformal_pvalue": round(cell_p, 4), "conformal_floor": round(floor, 4),
              "n_cells": n_cells, "conformal_abstained": not conformal_detected,
              "abstain_reason": "underpowered: floor 1/(n+1) > alpha (no benign population)"}
    ref = f"distinct-count-fanout|{entity}|{ent_bin}"
    verdict = emit_detection_verdict(
        ref, technique="T1558.003", pvalue=cell_p, params=params,
        what=TRUE, calibration=None, track_custody=False,   # check omitted — conformal abstained (see above)
    )
    root = build_detection_root(ref, params)
    shacl = validate(root)
    c = verdict.to_contract()

    print("=" * 88)
    print(f"DETECTION: account {entity} requested {distinct} distinct services in a {_GRAIN//60}-min bin.")
    print(f"           distinct-count > {_THRESHOLD} FIRED.  conformal entropy ABSTAINED: {n_cells} cells, "
          f"floor {floor:.3f} > α {_ALPHA:g}.")
    print(f"           (real atomic-red-team capture, no benign background — krbtgt-spray, not classic roast)")
    print("=" * 88)

    def line(label, value, status):
        print(f"  {label:18s} {str(value):26s} [{status}]")

    print("\nWHAT IT IS (the result):")
    line("technique", c["technique"], "asserted (folder label; really a spray variant)")
    line("decision", c["decision"], "MECHANICAL — threshold ∃-detect = TRUE")
    line("score", f"{c['score']:.4f}", "computed from observed rarity p — but UNCALIBRATED (see below)")

    print("\nWHO/WHAT/WHEN (the grounding):")
    w = c["w_record"]
    line("who", w["who"], "grounded — the account is identified")
    line("what", w["what"], "MECHANICAL — the threshold ∃-detect")
    line("when", w["when"], "ABSENT (none) — no temporal ∀-validate run")
    line("w_record.score", f"{w['score']:.2f}", "MECHANICAL — who+what TRUE, rest honestly none")

    print("\nHOW SURE / HOW SOUND (the epistemics — where the honesty lives):")
    line("conformal arm", "NONE (underpowered)", f"HONEST NONE — p={cell_p:.3f} ≥ floor {floor:.3f} ≥ α; abstains")
    line("cross_check", c.get("cross_check", "OMITTED"), "OMITTED — redundant measure abstained; kjoin can't carry it")
    line("calibration", c.get("calibration"), "ABSENT — threshold prior carries no distribution-free bound")
    line("score (uncalib.)", f"{c['score']:.3f}", "rarity vs the 42-cell ATTACK pop itself — no benign null")
    line("guarantee.tier", c["guarantee"]["tier"], "EARNED floor — well_formed only; NO bounded claim")
    line("custody", c.get("custody", "parked"), "PARKED — unsigned XML feed (precondition absent)")
    line("trustworthiness", c.get("trustworthiness", "parked"), "PARKED — with custody")

    print("\nWHERE IT CAME FROM (the justification):")
    line("provenance CID", c["provenance"][:24] + "…", "content-addressed root (records abstain_reason)")
    line("SHACL conforms", shacl.conforms, "MECHANICAL — self-falsifying shapes")

    print("\n" + "-" * 88)
    print("Contrast worked_example_spray_verdict (large population): there conformal FIRED, cross_check")
    print("AGREED (corroborated), calibration was ATTACHED (distribution-free FAR bound). Here, on an")
    print("isolated attack capture, the substrate refuses to fake any of that: the population statistic is")
    print("an explicit NONE-with-reason, the cross-check is uncorroborated, calibration is absent, and only")
    print("the well_formed floor is earned. The alert HONESTLY reads as a prior-driven flag, not a")
    print("calibrated detection — the system reporting its own applicability instead of hiding it.")


if __name__ == "__main__":
    main()
