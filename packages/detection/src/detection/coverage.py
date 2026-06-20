"""Stage 5 — per-TTP structural coverage report (the treatment pipeline's coverage stage).

`web/per_ttp_coverage_layers.html` models a technique's coverage as a *stack of layers*, not a "≥1 rule"
boolean. This module computes the **structural** layers — the ones derivable from the corpus alone, no events
or labels:

- **primitive** — the match-ops the technique's rules use (``endswith`` / ``contains`` / ``eq`` / ``re`` …);
  the alphabet of discriminators.
- **atom** — distinct positive clauses ``(field, mods, values)`` across the technique's rules (the molecules
  the rules are built from).
- **rule** — count of evaluable rules tagged with the technique.
- **concept** — distinct structural concepts = ``exactMatch`` dedup classes (rules with identical positive
  clause-sets count once). The ``rules / concepts`` ratio is **structural** redundancy.

On top of the structural layers sits one **behavioral, event-gated** layer:

- **corroboration** — for a technique exercised by event scenarios (``event_specs``), how many *independent
  witnesses* (deduped community rule-classes) actually fire (``sigma_panel.corroboration_coverage``). This is
  the airplane-redundant-control count: ``CORROBORATED`` when ≥1 external witness confirms, with honest named
  negatives (``no-overlap`` / ``no-same-logsource`` / ``not-evaluable``) otherwise. It is **NONE** when no
  events are supplied — never asserted — exactly like the pipeline's other event-gated stages.

Three honesty rails, all load-bearing:

1. **Gaps are NONE, not zero-coverage.** A requested technique with no evaluable rule is recorded in
   ``gaps`` — an absence of evidence, never asserted as "0% covered."
2. **The catch-class layer is deferred, not computed.** "Same instances caught = same detection" is
   *behavioral* and needs catch-set grounding (stage 4). So ``redundancy_ratio`` here is a structural
   **upper bound** (the dedup pass showed ``exactMatch`` over-groups); whether two same-concept rules are
   *purposeless duplicates* or *independent redundant witnesses* (the airplane-control distinction) is a
   verdict-assembly question grounding answers, not this stage.
3. **Corroboration is event-bounded, never corpus-wide.** It reports "corroborated *here*" for the supplied
   scenarios; absent a scenario the field is NONE, not False.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from detection.audit import _techniques                 # the canonical ATT&CK-tag extractor
from detection.rule_ir import CompiledRule
from detection.rule_lattice import clause_set, exact_classes


def _concept_map(lattice: dict) -> dict[str, str]:
    """``rule_id -> concept_id``: members of an ``exactMatch`` class share one id; every other rule is its
    own concept. Lets us count distinct structural concepts among an arbitrary subset of rules."""
    cmap: dict[str, str] = {}
    for i, cls in enumerate(exact_classes(lattice)):
        for rid in cls:
            cmap[rid] = f"concept:{i}"
    return cmap


def _families(lattice: dict, ids: set[str]) -> list[tuple[str, list[str]]]:
    """``(general, [variants])`` subsumption families restricted to rule ids in ``ids`` — the navigable
    general→specific structure within one technique (from ``broader``/``narrower`` edges)."""
    kids: dict[str, set[str]] = defaultdict(set)
    for a, rel, b, *_ in lattice["edges"]:
        if rel == "broader" and a in ids and b in ids:        # a ⊃ b: a general, b specific
            kids[a].add(b)
        elif rel == "narrower" and a in ids and b in ids:      # b ⊃ a
            kids[b].add(a)
    return [(g, sorted(v)) for g, v in sorted(kids.items())]


def coverage_report(rules: list[dict], compiled: list[CompiledRule], lattice: dict, techniques,
                    *, event_specs: list[dict] | None = None) -> dict:
    """The per-TTP coverage report. ``rules`` are the raw (tagged) evaluable dicts, ``compiled`` their IRs,
    ``lattice`` the stage-3 relation lattice, ``techniques`` the requested scope. ``event_specs`` (optional,
    each ``{technique, logsource, events, note?}``) turns on the behavioral **corroboration** layer per
    technique; when omitted, that layer is honestly ``None`` (event-gated)."""
    requested = sorted({str(t).upper() for t in techniques})
    ir_by_id = {ir.rule_id: ir for ir in compiled}
    tech_by_id = {r.get("id", "?"): _techniques(r) for r in rules if r.get("id", "?") in ir_by_id}
    cmap = _concept_map(lattice)

    per: dict[str, dict] = {}
    covered: list[str] = []
    for tech in requested:
        ids = {rid for rid, ts in tech_by_id.items() if tech in ts}
        if not ids:
            continue                                          # honest NONE — surfaces in `gaps`, not here
        covered.append(tech)
        atoms: set[tuple] = set()
        prims: Counter = Counter()
        for rid in ids:
            for field, mods, values in clause_set(ir_by_id[rid]):
                atoms.add((field, mods, values))
                prims[mods or ("eq",)] += 1
        concepts = {cmap.get(rid, rid) for rid in ids}
        per[tech] = {
            "rules": len(ids),
            "concepts": len(concepts),
            "redundancy_ratio": round(len(ids) / len(concepts), 2),   # STRUCTURAL upper bound (see caveat)
            "atoms": len(atoms),
            "primitives": {"/".join(k): v for k, v in sorted(prims.items())},
            "families": len(_families(lattice, ids)),
            "corroboration": None,                            # event-gated behavioral layer — set below
        }

    # behavioral layer (event-gated): how many independent witnesses fire on the supplied scenarios
    if event_specs:
        from detection.sigma_panel import corroboration_coverage
        corro = {r["technique"].upper(): r for r in corroboration_coverage(event_specs)}
        for tech, t in per.items():
            c = corro.get(tech)
            if c:                                             # witnesses=deduped classes that fired (votes)
                t["corroboration"] = {"category": c["category"], "witnesses": c["votes"],
                                      "fired": c["fired"], "note": c.get("note", "")}

    gaps = [t for t in requested if t not in covered]
    return {
        "requested": requested,
        "covered": covered,
        "gaps": gaps,                                         # NONE, not FALSE — absent telemetry/rules
        "per_technique": per,
        "layers": ["primitive", "atom", "rule", "concept", "corroboration"],  # catch-class still deferred (stage 4)
        "corroboration_enabled": bool(event_specs),          # honest: behavioral layer off unless events given
        "caveat": "structural layers corpus-derivable; corroboration is event-bounded (NONE without specs); "
                  "concepts=exactMatch dedup (upper bound); true redundancy/catch-class awaits catch-set",
    }
