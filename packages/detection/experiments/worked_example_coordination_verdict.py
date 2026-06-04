"""Worked example — a coordination detection, its whole justification walked (synthetic, always runs).

The companion to the fan-out worked example, chosen because coordination is the MOST DIFFERENT family:
its calibrator is FDR (not conformal), its cross-check is MI ⟷ Pearson correlation (not distinct⟷entropy),
and it can produce a `both`. Same justified verdict SHAPE, different CONTENT — the point of the milestone.

Run:  uv run python packages/detection/experiments/worked_example_coordination_verdict.py
"""

from detection._verdict import build_detection_root
from detection.coordination import (
    BEACON_COORDINATION,
    coordination_verdict,
    detect_coordination,
    synthesize_coordination_events,
)
from provenance import validate

_CORPUS = dict(n_normal=7, n_compromised=3, n_windows=300, rate=0.32, beacon_rate=0.15, grain_seconds=600, seed=7)
_DETECT = dict(grain_seconds=600, q=0.05, n_perm=499, seed=1000)


def main() -> None:
    events, _ = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    det = res["detected"][0]  # one coordinated host pair
    verdict = coordination_verdict(det, BEACON_COORDINATION)

    ref = f"{BEACON_COORDINATION.name}|{det.host_a}|{det.host_b}"
    root = build_detection_root(ref, {"host_a": det.host_a, "host_b": det.host_b,
                                      "mi_bits": det.mi, "technique": BEACON_COORDINATION.technique})
    shacl = validate(root)
    c = verdict.to_contract()

    print("=" * 78)
    print(f"DETECTION: coordinated pair {det.host_a} ⟷ {det.host_b} — MI {det.mi:.3f} bits,")
    print(f"           Pearson correlation {det.correlation:.3f} (the independent linear measure).")
    print("=" * 78)

    def line(label, value, status):
        print(f"  {label:16s} {str(value):28s} [{status}]")

    print("\nWHAT IT IS:")
    line("technique", c["technique"], "asserted (ATT&CK C2 label)")
    line("decision", c["decision"], "MECHANICAL — kjoin(detect=TRUE, when=none) = TRUE")
    line("score", f"{c['score']:.4f}", "computed — LLR (nominal Pd 0.9 × permutation pfa)")
    print("\nWHO/WHAT/WHEN:")
    w = c["w_record"]
    line("who", w["who"], "grounded — the host PAIR is identified")
    line("what", w["what"], "MECHANICAL — the ∃-detect (MI > null)")
    line("when", w["when"], "ABSENT (none) — coordination runs no temporal ∀-validate")
    line("w_record.score", f"{w['score']:.2f}", "MECHANICAL — 2/5 W's TRUE (who+what)")
    print("\nHOW SURE / HOW SOUND:")
    line("guarantee.tier", c["guarantee"]["tier"], "claimed — the well_formed FLOOR")
    line("calibration", f"{c['calibration']['method']} FAR≤{c['calibration']['far_bound']}",
         "ATTACHED — FDR level q (NOT conformal — different family, same slot)")
    line("cross_check", c["cross_check"], "MECHANICAL — MI ⟷ correlation agree (positive)")
    line("custody", c["custody"], "ABSENT (none) — synthetic corpus, honest")
    line("trustworthiness", c["trustworthiness"], "DERIVED — kjoin(custody, validity)")
    print("\nWHERE IT CAME FROM:")
    line("provenance CID", c["provenance"][:24] + "…", "content-addressed root")
    line("SHACL conforms", shacl.conforms, "MECHANICAL — self-falsifying shapes")

    print("\n" + "-" * 78)
    print("SAME justified SHAPE as fan-out; DIFFERENT content: the calibrator is FDR (q), the")
    print("cross-check is MI⟷correlation. The substrate standardized the receipts, not the mechanics.")
    print("(Cross-check MECHANICS are wired; whether a `both` catches a real coupling is deferred.)")


if __name__ == "__main__":
    main()
