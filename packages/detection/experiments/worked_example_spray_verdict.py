"""Worked example — one real detection, its WHOLE justification walked.

The proof artifact for canon's current state: take one real labeled password-spray from the
``faker-kerberos`` corpus, produce its :class:`~forge_core.DetectionVerdict`, and walk *every* attached
claim — what it is, and whether it is **mechanically checked**, **honestly absent**, or **asserted**.
This is the "high-quality output on real data" the substrate is for: an alert that carries its receipts.

Run:  uv run python packages/detection/experiments/worked_example_spray_verdict.py
(needs the faker-kerberos corpus at ~/data/faker-kerberos/v1/export.csv and the [rdf] extra).
"""

from pathlib import Path

from detection._verdict import build_detection_root
from detection.fanout import PASSWORD_SPRAY, fanout_verdict, run_binding
from provenance import validate

_DATA = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"


def main() -> None:
    if not _DATA.exists():
        raise SystemExit(f"corpus absent: {_DATA}")

    # 1. real detection: account fan-out at a 10-min grain → the labeled spray source IPs.
    result = run_binding(str(_DATA), PASSWORD_SPRAY)
    det = next(d for d in result["detected"] if d.cell.entity == "10.3.27.24")  # one labeled spray IP
    verdict = fanout_verdict(det, PASSWORD_SPRAY)

    # the verdict's provenance root (same construction emit_detection_verdict uses) — for the SHACL walk.
    ref = f"{PASSWORD_SPRAY.name}|{det.cell.entity}|{det.cell.bin}"
    root = build_detection_root(ref, {"entity": det.cell.entity, "bin": det.cell.bin,
                                      "technique": PASSWORD_SPRAY.technique})
    shacl = validate(root)

    c = verdict.to_contract()
    print("=" * 78)
    print(f"DETECTION: password spray — source IP {det.cell.entity} touched {det.cell.distinct} distinct")
    print(f"           accounts in 10-min bin {det.cell.bin}; entropy {det.cell.entropy:.2f} bits.")
    print("=" * 78)

    def line(label, value, status):
        print(f"  {label:16s} {str(value):28s} [{status}]")

    print("\nWHAT IT IS (the result):")
    line("technique", c["technique"], "asserted (ATT&CK label)")
    line("decision", c["decision"], "MECHANICAL — kjoin(detect=TRUE, when=none) = TRUE")
    line("score", f"{c['score']:.4f}", "computed — LLR fusion (nominal Pd 0.9 × conformal pfa)")

    print("\nWHO/WHAT/WHEN (the grounding):")
    w = c["w_record"]
    line("who", w["who"], "grounded — the source IP is identified")
    line("what", w["what"], "MECHANICAL — the ∃-detect")
    line("when", w["when"], "ABSENT (none) — fan-out runs no temporal ∀-validate")
    line("where/how", f"{w['where']}/{w['how']}", "ABSENT (none) — honestly unknown")
    line("w_record.score", f"{w['score']:.2f}", "MECHANICAL — 2/5 W's TRUE (who+what; when honestly none)")

    print("\nHOW SURE / HOW SOUND (the epistemics):")
    line("guarantee.tier", c["guarantee"]["tier"], "claimed — the well_formed FLOOR (default on this path)")
    line("calibration", f"{c['calibration']['method']} FAR≤{c['calibration']['far_bound']}",
         "ATTACHED — distribution-free bound")
    line("cross_check", c["cross_check"], "MECHANICAL — distinct⟷entropy agree")
    line("custody", c["custody"], "ABSENT (none) — unsigned CSV, honest")
    line("validity", c["validity"]["verdict"], "unchecked — no payload schema")
    line("trustworthiness", c["trustworthiness"], "DERIVED — kjoin(custody, validity)")

    print("\nWHERE IT CAME FROM (the justification):")
    line("provenance CID", c["provenance"][:24] + "…", "content-addressed root")
    line("SHACL conforms", shacl.conforms, "MECHANICAL — self-falsifying shapes")

    print("\n" + "-" * 78)
    print("Every claim above is either mechanically checked, honestly marked absent (none),")
    print("or an explicit assertion — and all of it is ATTACHED to the verdict, walkable from")
    print(f"the provenance CID. The alert carries its receipts. (custody/trust honestly NONE:")
    print(" an unsigned CSV is not attested evidence — the substrate refuses to fake it.)")


if __name__ == "__main__":
    main()
