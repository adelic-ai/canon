"""Stage 3 — FCA. Pins that concepts group by the chosen projection, that a coarse (value-blind) projection
collapses what a fine (value-aware) one separates, and that the projection is a free parameter (no hardcoded
key). The corpus test reproduces the over-collapse end to end through omega's own pipeline."""

import os
from pathlib import Path

import pytest

from omega.axes import CONTENT, FIELD_SET
from omega.fca import concepts, subsumes
from omega.ingest.sigma import load, load_ir, to_ir

SIGMA = Path(os.environ["OMEGA_SIGMA_CORPUS"]) if os.environ.get("OMEGA_SIGMA_CORPUS") else \
    Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"

_LS = "logsource: {product: windows, category: process_creation}"
_RULES = f"""\
title: A
{_LS}
detection:
  selection: {{Image|endswith: '\\a.exe'}}
  condition: selection
---
title: B
{_LS}
detection:
  selection: {{Image|endswith: '\\b.exe'}}
  condition: selection
---
title: C
{_LS}
detection:
  selection: {{Image|endswith: '\\a.exe', CommandLine|contains: 'x'}}
  condition: selection
"""


def _irs(tmp_path):
    (tmp_path / "r.yml").write_text(_RULES)
    rules, _ = load(tmp_path)
    return [to_ir(r) for r in rules]


def test_value_blind_collapses_value_aware_separates(tmp_path):
    irs = _irs(tmp_path)
    # value-BLIND: A and B both read only {Image} -> one concept collapses them (C adds CommandLine -> its own)
    blind = concepts(irs, axes=FIELD_SET)
    assert blind.n_rules == 3
    assert any(c.size == 2 for c in blind.collapsed)          # A,B collapsed
    # value-AWARE: different Image values -> all three distinct
    aware = concepts(irs, axes=CONTENT)
    assert aware.n_concepts == 3 and not aware.collapsed


def test_projection_is_a_free_parameter(tmp_path):
    irs = _irs(tmp_path)
    # the SAME rules, different axis-sets -> different concept counts. sameness is a family, not a fixed key.
    assert concepts(irs, axes={"field"}).n_concepts != concepts(irs, axes={"clause"}).n_concepts


def test_subsumption_order(tmp_path):
    irs = _irs(tmp_path)
    aware = {tuple(sorted(c.attributes)): c for c in concepts(irs, axes={"clause"}).concepts}
    a = next(c for c in aware.values() if any("a.exe" in x for x in c.attributes) and len(c.attributes) == 1)
    c = next(cc for cc in aware.values() if len(cc.attributes) == 2)   # C: Image=a.exe AND CommandLine
    assert subsumes(c, a)          # C is narrower than A (superset of clauses -> stricter)
    assert not subsumes(a, c)


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored corpus not present")
def test_over_collapse_corpus_wide():
    compiled, _ = load_ir(SIGMA)
    blind = concepts(compiled, axes=FIELD_SET)
    aware = concepts(compiled, axes=CONTENT)
    assert blind.n_rules == aware.n_rules >= 3700
    # value-blind collapses HARD (fields only); value-aware separates nearly all
    assert blind.n_concepts < aware.n_concepts // 3
    # pure-logic value-aware leaves a SMALL residue of genuine collapses: rules with byte-identical logic
    # differing only in logsource (same detection authored per platform/channel) — a finding, not noise.
    assert 0 < len(aware.collapsed) < 30
    assert aware.n_concepts == aware.n_rules - sum(c.size - 1 for c in aware.collapsed)


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored corpus not present")
def test_logsource_axis_resolves_the_pure_logic_residue():
    """Adding the logsource axis splits the same-logic/different-source pairs back apart — showing the residue
    is context, not true duplication, and that the projection is the knob."""
    compiled, _ = load_ir(SIGMA)
    pure = concepts(compiled, axes=CONTENT)
    with_ctx = concepts(compiled, axes=CONTENT | {"logsource"})
    assert with_ctx.n_concepts > pure.n_concepts           # context refines the residue apart
    assert with_ctx.n_concepts == with_ctx.n_rules         # every rule distinct once source context is in
