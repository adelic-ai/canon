"""Rust emitter bridge — fire the detection IR through the native ``motif-rs`` crate (the hot path).

The IR (``rule_ir.CompiledRule``) is language-neutral; this emits it to the Rust interpreter via a subprocess
(JSON in, firings out) and **attests** the Rust path faithful to the Python oracle (``eval_ir``) over a corpus —
the licence to run the fast path in production. Rust handles the glob/string/keyword + boolean-condition core;
clauses with modifiers it doesn't implement yet (``re``/``cidr``/``gt|lt``/``windash``) are marked *unsupported*
and the gate skips them (abstain, never mis-fire). Event values are str-coerced here (Python-side), so Rust gets
strings and the coercion semantics match by construction.

``motif-rs`` is built out-of-tree (``rust/motif-rs``); if the binary isn't present, :func:`rust_available` is
False and the consumers skip — same pattern as the corpus-gated tests.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

_BINARY = Path(__file__).parents[4] / "rust/motif-rs/target/release/motif-rs"


def rust_available() -> bool:
    return _BINARY.exists()


def eval_rust(compiled_rules, events: list[dict]) -> tuple[list[list[bool]], list[bool]]:
    """Run the Rust emitter over ``(compiled_rules, events)``. Returns ``(results, supported)``:
    ``results[i][j]`` = does rule *i* fire on event *j*; ``supported[i]`` = whether Rust handled rule *i*."""
    payload = {
        "rules": [r.to_dict() for r in compiled_rules],
        "events": [{k: str(v) for k, v in e.items()} for e in events],   # Python-side str-coercion
    }
    proc = subprocess.run([str(_BINARY)], input=json.dumps(payload),
                          capture_output=True, text=True, check=True)
    out = json.loads(proc.stdout)
    return out["results"], out["supported"]


def attest_rust_agreement(rule_dicts: list[dict], events: list[dict]) -> dict:
    """Faithfulness gate: the Rust emitter agrees with :func:`~detection.rule_ir.eval_ir` on every **supported**
    rule × event — the licence to run Rust in production. ``rule_dicts`` are raw evaluable Sigma rule dicts."""
    from detection.rule_ir import compile_rule, eval_ir

    compiled = [compile_rule(r) for r in rule_dicts]
    results, supported = eval_rust(compiled, events)
    dis = []
    for i, (ir, sup) in enumerate(zip(compiled, supported)):
        if not sup:
            continue
        for j, e in enumerate(events):
            if results[i][j] != eval_ir(ir, e):
                dis.append({"rule": ir.rule_id, "event": j})
    n_sup = sum(supported)
    return {"n_rules": len(compiled), "n_supported": n_sup,
            "checked": n_sup * len(events), "disagreements": dis, "faithful": not dis}
