"""The atom→TTP inverted index — routing + specificity (IDF), signed by polarity.

Atoms are shared across rules; rules detect TTPs. So each atom carries an induced **TTP-set** — the
inverted index ``{atom_id: {technique: signs}}`` (design/ir_canonical_ruleset.md Corollary 1). It is not
bookkeeping:

- **Spread = specificity ≈ IDF.** An atom in *many* TTPs is generic and weak evidence for any one
  (``Image endswith \\rundll32.exe`` spans T1003.001, T1218, …); an atom in *few* is a discriminator
  (``CallTrace contains comsvcs.dll`` ≈ T1003.001). :func:`specificity` = the count; it is the per-atom
  evidence weight, free from the index.
- **Membership is signed.** An atom can be a positive selector or a negative filter (``not filter`` — an
  *exclusion*). The polarity comes from the condition AST (an odd number of enclosing ``not``s ⇒ ``-1``);
  otherwise an exclusion would be miscounted as evidence-*for*.
- **Tag-claimed, for now.** Techniques are read from the rules' ATT&CK tags — lossy (the 79-claim /
  2-catch problem). The *grounded* version ("TTPs whose labeled instances the atom fires on") is the
  catch-set, synthcyber-gated. This module is the tag-claimed layer.

An atom *participates in* a TTP; it does not *detect* one — the TTP is confirmed when its composition's
atoms co-fire. So this index is membership/routing + weighting; firing stays the composition.
"""

from __future__ import annotations

import fnmatch
import re
from collections import defaultdict

from detection.atoms import clause_atom_id, keyword_atom_id
from detection.rule_ir import compile_rule
from detection.sigma_eval import is_evaluable

_ATTACK = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _techniques(rule: dict) -> set[str]:
    """ATT&CK technique ids from the rule's tags (e.g. ``attack.t1003.001`` → ``T1003.001``)."""
    return {m.group(1).upper() for t in (rule.get("tags") or []) if (m := _ATTACK.search(str(t)))}


def block_polarities(ir) -> dict[str, set[int]]:
    """Per referenced block, its polarity in the condition: ``+1`` positive (selector), ``-1`` negative
    (under an odd number of ``not``s — an exclusion/filter). Quantifier patterns (``1 of sel_*``,
    ``all of them``) expand to matching block names at the current sign. A block can carry both signs if
    it is referenced both ways (rare)."""
    names = list(ir.block_map())
    pol: dict[str, set[int]] = defaultdict(set)

    def walk(node, sign: int) -> None:
        kind = node[0]
        if kind == "ref":
            pol[node[1]].add(sign)
        elif kind == "not":
            walk(node[1], -sign)
        elif kind in ("and", "or"):
            for n in node[1]:
                walk(n, sign)
        elif kind == "quant":
            pat = node[2]
            matched = names if pat in ("them", "*", None) else [b for b in names if fnmatch.fnmatch(b, pat)]
            for b in matched:
                pol[b].add(sign)

    walk(ir.condition, 1)
    return dict(pol)


def build_atom_index(rules: list[dict]) -> dict[str, dict[str, list[int]]]:
    """Build the inverted index ``{atom_id: {technique: sorted signs}}`` over raw Sigma rule dicts.
    Skips non-evaluable rules and rules with no ATT&CK tag. Tag-claimed (techniques from tags), signed
    (polarity from the condition); an unreferenced block defaults to positive."""
    idx: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    for r in rules:
        if not isinstance(r, dict) or not is_evaluable(r):
            continue
        techs = _techniques(r)
        if not techs:
            continue
        ir = compile_rule(r)
        pol = block_polarities(ir)
        for b in ir.blocks:
            signs = pol.get(b.name, {1})                      # unreferenced block → positive default
            aids = ([keyword_atom_id(str(k)) for k in b.keywords] if b.kind == "keyword"
                    else [clause_atom_id(c) for m in b.maps for c in m])
            for aid in aids:
                for t in techs:
                    idx[aid][t] |= signs
    return {aid: {t: sorted(s) for t, s in d.items()} for aid, d in idx.items()}


def specificity(index: dict, atom_id: str) -> int:
    """Number of distinct TTPs an atom participates in — its spread. Higher = more generic = weaker
    evidence for any one technique (the IDF intuition). 1 = a near-exclusive discriminator."""
    return len(index.get(atom_id, {}))


def techniques_for(index: dict, atom_id: str) -> dict[str, list[int]]:
    """The signed TTP-set for an atom: ``{technique: [signs]}`` (``[1]`` selector, ``[-1]`` exclusion)."""
    return index.get(atom_id, {})


def candidate_techniques(index: dict, fired_atom_ids) -> set[str]:
    """Route fired atoms to the candidate techniques whose detections they POSITIVELY participate in —
    the pruning step of the firing scheme (only techniques an atom selects-for are candidates; a purely
    negative/exclusion participation does not nominate a technique)."""
    out: set[str] = set()
    for aid in fired_atom_ids:
        for t, signs in index.get(aid, {}).items():
            if 1 in signs:
                out.add(t)
    return out
