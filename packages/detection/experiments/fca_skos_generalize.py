"""Generalization check for the FCA over-collapse claim — does value-blindness bite across EVERY Sigma
product, or was macOS cherry-picked? For each ``logsource.product`` (with ≥10 evaluable rules) we count FCA
concepts under the value-BLIND field-set key vs the value-AWARE content key, and the worst single field-set
class with how the content key splits it. If content ≫ field-set everywhere, the result generalizes.

Run: ``uv run --project packages/detection python packages/detection/experiments/fca_skos_generalize.py``
Writes fca_skos_generalize.json next to this script.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

import yaml

from detection.rule_ir import compile_rule
from detection.sigma_eval import is_evaluable
from detection.sigma_panel import SIGMA, content_signature, signature

OUT = Path(__file__).parent


def main() -> dict:
    by_product: dict[str, list] = collections.defaultdict(list)
    for p in sorted(SIGMA.rglob("*.yml")):
        try:
            r = yaml.safe_load(p.read_text(errors="replace"))
        except Exception:
            continue
        if not isinstance(r, dict) or not isinstance(r.get("detection"), dict) or not is_evaluable(r):
            continue
        product = (r.get("logsource") or {}).get("product") or "(none)"
        by_product[product].append((p.name, r))

    rows = []
    for product, rules in by_product.items():
        irc = {}
        for name, r in rules:
            try:
                irc[name] = compile_rule(r)
            except Exception:
                pass
        rules = [(n, r) for n, r in rules if n in irc]
        if len(rules) < 10:
            continue
        by_name = dict(rules)
        fieldset = collections.defaultdict(list)
        content = set()
        for name, r in rules:
            fieldset[signature(r)].append(name)
            content.add(content_signature(r, ir=irc[name]))
        big_key, big_names = max(fieldset.items(), key=lambda kv: len(kv[1]))
        big_content = len({content_signature(by_name[n], ir=irc[n]) for n in big_names})
        rows.append({
            "product": product,
            "n_rules": len(rules),
            "fieldset_concepts": len(fieldset),                 # value-BLIND
            "content_concepts": len(content),                   # value-AWARE
            "split_factor": round(len(content) / len(fieldset), 1),
            "biggest_fieldset_class": len(big_names),
            "biggest_class_content_split": big_content,
        })
    rows.sort(key=lambda x: -x["n_rules"])
    out = {"products": rows,
           "generalizes": all(x["content_concepts"] > x["fieldset_concepts"] for x in rows)}
    (OUT / "fca_skos_generalize.json").write_text(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    res = main()
    print(f"{'product':14} {'rules':>6} {'fieldset':>9} {'content':>8} {'split':>6}  biggest-class→content-split")
    print("-" * 78)
    for x in res["products"]:
        print(f"{x['product']:14} {x['n_rules']:6} {x['fieldset_concepts']:9} {x['content_concepts']:8} "
              f"{x['split_factor']:6}  {x['biggest_fieldset_class']:>4} → {x['biggest_class_content_split']}")
    print("-" * 78)
    print(f"value-aware key > value-blind key for EVERY product: {res['generalizes']}")
    print("wrote fca_skos_generalize.json")
