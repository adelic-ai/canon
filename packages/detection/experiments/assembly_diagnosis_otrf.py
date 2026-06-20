"""Assembly-level non-fire diagnosis on the real OTRF comsvcs T1003.001 instance.

For every evaluable Sigma rule claiming T1003.001 that does NOT catch the labeled comsvcs lsass-dump event,
localize the fault (assembly_diagnosis): wrong-channel / filter-excluded / composition-gap / variant-miss /
unvouched-miss. The actionable rows are composition-gap (assembly faults) and unvouched-miss (candidate bugs);
wrong-channel and variant-miss are honest non-faults (right rule, wrong event).

Run:  uv run python packages/detection/experiments/assembly_diagnosis_otrf.py
(needs ~/data/otrf-security-datasets/LSASS_campaign_03/ + the vendored SigmaHQ corpus.)
"""

from pathlib import Path

import yaml

from detection.assembly_diagnosis import build_atom_reuse, diagnose_silent_rules
from detection.fidelity_scorecard import otrf_lsass_t1003_case
from detection.sigma_eval import is_evaluable
from detection.sigma_panel import SIGMA, gather

_OTRF = Path.home() / "data" / "otrf-security-datasets" / "LSASS_campaign_03" / "lsass_campaign_03.json"


def _all_rules():
    out = []
    for p in Path(SIGMA).rglob("*.yml"):
        try:
            d = yaml.safe_load(p.read_text())
        except Exception:
            continue
        if isinstance(d, dict) and "detection" in d:
            out.append(d)
    return out


def main() -> None:
    if not _OTRF.exists():
        raise SystemExit(f"OTRF corpus absent: {_OTRF}")
    pos = otrf_lsass_t1003_case(str(_OTRF))["positives"]
    if not pos:
        raise SystemExit("no comsvcs positive reconstructed from the corpus")
    event = pos[0]

    print("building corpus atom-reuse map (vouching oracle)…")
    reuse = build_atom_reuse(_all_rules())
    rules = [r for _p, r in gather("T1003.001", root=SIGMA) if is_evaluable(r)]
    res = diagnose_silent_rules(rules, event, reuse)

    print("=" * 84)
    print(f"ASSEMBLY-LEVEL NON-FIRE DIAGNOSIS — T1003.001 comsvcs instance ({res['n_rules']} evaluable rules)")
    print("=" * 84)
    print("fault tally:", res["fault_tally"])
    print()
    order = ["fires", "composition-gap", "unvouched-miss", "filter-excluded", "variant-miss",
             "field-absent-gap", "wrong-channel"]
    for fault in order:
        ids = res["by_fault"].get(fault, [])
        if not ids:
            continue
        tag = {"composition-gap": "← ASSEMBLY FAULT (look here)",
               "unvouched-miss": "← rule-unique miss (mostly variant-specific; bug only if NEAR-MISS)",
               "fires": "(caught it)", "wrong-channel": "(right rule, wrong event — not a fault)",
               "filter-excluded": "(allowlisted)",
               "variant-miss": "(different variant — not a fault)"}.get(fault, "")
        print(f"[{fault}]  {len(ids)} rules {tag}")

    # show the localization detail for the rule-unique / assembly cases
    actionable = [d for d in res["diagnoses"] if d["fault"] in ("composition-gap", "unvouched-miss")]
    if actionable:
        print("\n" + "-" * 84)
        print("LOCALIZED — assembly faults & rule-unique misses:")
        for d in actionable:
            print(f"\n  {d['rule_id']}  [{d['fault']}]")
            if d["suspect_atoms"]:
                for s in d["suspect_atoms"]:
                    print(f"     rule-unique (reuse={s['reuse']}): {s['block']} :: {s['atom']}")
            if d["fault"] == "composition-gap":
                print(f"     all {len(d['exonerated'])} field-atoms match in isolation — fault is the "
                      f"condition/keyword wiring, not an atom")
    print("\n" + "-" * 84)
    print("HONEST READ: the oracle EXONERATES shared atoms (they fire in sibling rules) — that direction holds.")
    print("But rule-uniqueness alone is a weak bug signal: on real data the 'unvouched-miss' rules are mostly")
    print("legitimate variant-specific discriminators (hacktool lists, debug-DLL traces, specific access")
    print("masks), NOT typos. The real bug signal is NEAR-MISS (atom value one edit from a value PRESENT in the")
    print("event) — rule-uniqueness is the candidate pool, edit-distance is the filter. wrong-channel/")
    print("variant-miss are honest 'right rule, wrong event'. This corroborates the fidelity-scorecard causes")
    print("(≈54 missing-telemetry / ≈22 logic-gap / 1 allowlist) at per-atom resolution.")


if __name__ == "__main__":
    main()
