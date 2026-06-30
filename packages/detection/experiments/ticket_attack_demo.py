"""Tiered Golden / Pass-the-Ticket detector on the synth-enterprise generator. Run:
``uv run --project packages/detection python packages/detection/experiments/ticket_attack_demo.py``.

Shows the warrant tier degrade with telemetry: a 2024-patched DC emits the Ticket Information hashes and
the detector does an exact cross-DC hash anti-join (catches Golden + PtT); an unpatched DC emits no hashes
and the detector falls back to a low-warrant account-level heuristic — keeping only the fabricated-account
Golden and honestly LOSING PtT + active-account Golden (NONE). Intra-DC-log; the hash fields are PROVISIONAL
(raw EventData names need confirming against a real patched-DC capture)."""

from detection.kerberos_tickets import detect_ticket_attacks_synth


def _report(patched: bool) -> None:
    r = detect_ticket_attacks_synth(seed=1, patched=patched)
    head = "PATCHED DC — hash tier" if patched else "UNPATCHED DC — metadata fallback"
    print(f"\n=== {head} === events={r['n_events']} injected_attacks={r['n_labeled_attacks']} "
          f"verdicts={len(r['verdicts'])}")
    for v in r["verdicts"]:
        print(f"  [{v['tier']:8}] {v['kind']:16} account={v['account']:24} ip={v['ip']}")
        print(f"             {v['evidence']}")
    if not r["verdicts"]:
        print("  (no verdicts)")


if __name__ == "__main__":
    _report(patched=True)
    _report(patched=False)
    print("\nNOTE: the hash tier catches all three (PtT, golden-on-active-user, golden-ghost) exactly and with "
          "no FP. Strip the hashes (unpatched DC) and only the fabricated-account golden survives — PtT and "
          "the active-user golden are undetectable from DC logs alone. The detector reports WHICH tier of "
          "evidence backed each verdict (hash / metadata / NONE) rather than pretending uniform coverage.")
