"""Co-firing demo — fire each technique's full Sigma rule bundle on the synth-enterprise labeled events
and print the catch-layer divergence. Run: ``uv run --project packages/detection python
packages/detection/experiments/cofire_synth_demo.py``.

Shows the claim≠catch gap on data whose labels we control, and that the rules which DO catch a technique
catch disjoint evidence. Intra-Sigma (no SPL/EQL engine here); test stand, not a recall oracle."""

from detection.cofire import cofire_synth


def _report(tech: str, variants=("rubeus", "powershell", "setspn")) -> None:
    r = cofire_synth(tech, seed=1, variants=variants)
    print(f"\n=== {tech} variants={list(variants)} === events={r['n_events']} "
          f"malicious={r['n_malicious']} benign={r['n_benign']}")
    print(f"  co-claiming evaluable rules: {r['rules_evaluable']}   catching: {r['rules_catching']}"
          f"   catch_rate: {r['catch_rate']}")
    print(f"  silent co-claimers by cause: {r['silent_causes']}")
    print(f"  catch-set divergence: caught_by_all={r['instances_caught_by_all_catchers']}"
          f" caught_by_one={r['instances_caught_by_one']} caught_by_none={r['instances_caught_by_none']}"
          f" mean_pairwise_jaccard={r['mean_pairwise_catch_jaccard']}")
    print(f"  clean catchers (catch + zero benign FP): {r['clean_catchers']}")
    print(f"  catchers WITH benign FP (over-broad on this data): {r['catchers_with_fps']}")
    for x in sorted(r["rows"], key=lambda x: -x["n_caught"]):
        if x["n_caught"] or x["fps"]:
            print(f"    fire  {x['rule']:55} caught={x['n_caught']:3} fps={x['fps']}")


if __name__ == "__main__":
    print("### kerberoast — single variant -> diverse tradecraft -> no-downgrade (the contrast) ###")
    _report("T1558.003", variants=("rubeus",))
    _report("T1558.003", variants=("rubeus", "powershell", "setspn", "aes_rig"))
    _report("T1558.003", variants=("aes_rig",))   # no RC4 downgrade -> every signature rule blind
    print("\n### lateral movement ###")
    for t in ("T1021", "T1021.001"):
        _report(t)
    print("\nNOTE: intra-Sigma only (ESCU/Elastic have no engine here); synth = test stand, not a recall "
          "oracle. Diverse tradecraft makes the COVERAGE/evasion axis rich: setspn surfaces a new catcher, "
          "the Rubeus rule is broader than its name, the stealth AES-downgrade evades the RC4 heuristic, and "
          "the no-downgrade rig roast (aes_rig) is caught by ZERO signature rules — only the structural "
          "fan-out / pivot / cross-host join could catch it. Catch-SET Jaccard stays 0 (single-witness per "
          "event); raising it needs rules that co-fire on one event.")
