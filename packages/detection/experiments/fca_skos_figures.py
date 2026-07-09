"""Reproducible figures for the essay "Are These Two Rules the Same?" — FCA *derives* the structure,
SKOS *expresses* the relations, and the irreducible residue is behavioral (the catch-set).

Runs over the in-repo SigmaHQ corpus (default: the macOS product slice the essay anchors on). Deterministic,
dependency-light. Prints a human-readable report and writes ``fca_skos_figures.json`` + ``fca_skos_lattice.ttl``
next to this script so the essay cites stable, regenerable numbers rather than asserted ones.

  Figure 1 — the over-collapse: FCA concept counts under the value-BLIND field-set key vs the value-AWARE
             content key. The field-set lumps structurally-distinct rules; content-awareness splits them.
  Figure 2 — a concrete, human-readable class: rules that share a field-set but match different values, so the
             field-set sees 1 concept and the content key sees N.
  Figure 3 — a worked SKOS-graded lattice: exact / close / broad / narrow / related edges with the why()
             justification (shared clauses + what each side has uniquely) and the SKOS predicate.

Run: ``uv run --project packages/detection python packages/detection/experiments/fca_skos_figures.py``
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

import yaml

from detection import rule_lattice as RL
from detection.rule_ir import compile_rule
from detection.sigma_eval import is_evaluable
from detection.sigma_panel import SIGMA, content_signature, signature

PRODUCT = "macos"
OUT = Path(__file__).parent


def load(product: str):
    """Every evaluable Sigma rule for ``logsource.product == product``, sorted by filename (deterministic)."""
    out = []
    for p in sorted(SIGMA.rglob("*.yml")):
        try:
            r = yaml.safe_load(p.read_text(errors="replace"))
        except Exception:
            continue
        if not isinstance(r, dict):
            continue
        ls = r.get("logsource") or {}
        if ls.get("product") == product and isinstance(r.get("detection"), dict) and is_evaluable(r):
            out.append((p.name, r))
    return out


def main() -> dict:
    rules = load(PRODUCT)
    by_name = dict(rules)
    ir = {name: compile_rule(r) for name, r in rules}

    # ── Figure 1 — over-collapse: value-blind field-set vs value-aware content key ────────────────────────
    fieldset = collections.defaultdict(list)
    content = collections.defaultdict(list)
    for name, r in rules:
        fieldset[signature(r)].append(name)
        content[content_signature(r, ir=ir[name])].append(name)
    biggest = max(fieldset.items(), key=lambda kv: len(kv[1]))
    big_names = set(biggest[1])
    big_content = {content_signature(by_name[n], ir=ir[n]) for n in big_names}
    fig1 = {
        "product": PRODUCT,
        "n_rules": len(rules),
        "fieldset_concepts": len(fieldset),          # value-BLIND
        "content_concepts": len(content),            # value-AWARE
        "biggest_fieldset_class": len(biggest[1]),
        "biggest_fieldset_fields": sorted(biggest[0][1]) or "(empty — keyword/whole-event rules)",
        "biggest_class_split_by_content": len(big_content),
    }

    # ── Figure 2 — a human-readable same-fields-different-values class (NON-empty field-set, ≥2 rules) ─────
    nonempty = {k: v for k, v in fieldset.items() if k[1] and len(v) >= 2}
    fig2 = None
    if nonempty:
        key, members = max(nonempty.items(), key=lambda kv: len(kv[1]))
        members = sorted(members)
        detail = []
        for name in members:
            cls = sorted(f"{f}{list(m) or ''}={list(v) if isinstance(v, (list, tuple)) else v}"
                         for (f, m, v) in RL.clause_set(ir[name]))
            detail.append({"rule": name, "clauses": cls})
        fig2 = {
            "shared_fieldset": sorted(key[1]),
            "n_rules_in_class": len(members),
            "fieldset_concepts_for_class": 1,
            "content_concepts_for_class": len({content_signature(by_name[n], ir=ir[n]) for n in members}),
            "members": detail,
        }

    # ── Figure 3 — a worked SKOS-graded lattice (relation grade + why + SKOS predicate) ───────────────────
    ir_by_id = {c.rule_id: c for c in ir.values()}                 # build_lattice keys edges by rule_id (UUID)
    id_to_name = {c.rule_id: name for name, c in ir.items()}
    lat = RL.build_lattice([ir[name] for name, _ in rules])
    exact_classes = RL.exact_classes(lat)
    examples = {}
    for rel in ("exact", "close", "narrower", "broader", "related"):
        edge = next((e for e in lat["edges"] if e[1] == rel), None)
        if edge:
            a, _rel, b, t = edge
            examples[rel] = {
                "a": id_to_name.get(a, a), "b": id_to_name.get(b, b), "tightness": t, "skos": RL.SKOS[rel],
                "why": RL.why(RL.clause_set(ir_by_id[a]), RL.clause_set(ir_by_id[b])),
            }
    fig3 = {
        "lattice_rules": lat["n_rules"],            # keyword-only rules drop out (no comparable structure)
        "edges": lat["n_edges"],
        "edge_type_counts": lat["counts"],
        "dedup_exact_classes": len(exact_classes),  # genuine synonym classes (structure-equal)
        "examples": examples,
    }

    figures = {"figure1_over_collapse": fig1, "figure2_value_class": fig2, "figure3_skos_lattice": fig3}
    (OUT / "fca_skos_figures.json").write_text(json.dumps(figures, indent=2))
    (OUT / "fca_skos_lattice.ttl").write_text(RL.to_turtle(lat))
    return figures


def _report(f: dict) -> None:
    f1, f2, f3 = f["figure1_over_collapse"], f["figure2_value_class"], f["figure3_skos_lattice"]
    print("=" * 78)
    print(f"FIGURE 1 — over-collapse ({f1['product']}, {f1['n_rules']} evaluable rules)")
    print(f"  value-BLIND  field-set key : {f1['fieldset_concepts']:3} concepts")
    print(f"  value-AWARE  content  key  : {f1['content_concepts']:3} concepts")
    print(f"  biggest field-set class    : {f1['biggest_fieldset_class']} rules share {f1['biggest_fieldset_fields']}")
    print(f"    → content key splits them into {f1['biggest_class_split_by_content']} concepts")
    if f2:
        print("\n" + "=" * 78)
        print(f"FIGURE 2 — a same-fields/different-values class ({f2['n_rules_in_class']} rules)")
        print(f"  shared field-set: {f2['shared_fieldset']}")
        print(f"  field-set sees {f2['fieldset_concepts_for_class']} concept; content sees "
              f"{f2['content_concepts_for_class']}")
        for m in f2["members"][:5]:
            print(f"    {m['rule']}")
            for c in m["clauses"][:3]:
                print(f"        {c}")
    print("\n" + "=" * 78)
    print(f"FIGURE 3 — SKOS-graded lattice ({f3['lattice_rules']} structured rules, {f3['edges']} edges)")
    print(f"  edge types: {f3['edge_type_counts']}   dedup(exact) classes: {f3['dedup_exact_classes']}")
    for rel, ex in f3["examples"].items():
        print(f"  [{ex['skos']:18}] {ex['a']}  ~  {ex['b']}  (tightness {ex['tightness']})")
        if ex["why"]["a_only"][:2] or ex["why"]["b_only"][:2]:
            print(f"      why: a_only={ex['why']['a_only'][:2]}  b_only={ex['why']['b_only'][:2]}")
    print("\nwrote fca_skos_figures.json + fca_skos_lattice.ttl")


if __name__ == "__main__":
    _report(main())
