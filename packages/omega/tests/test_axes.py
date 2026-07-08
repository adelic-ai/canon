"""Stage 2 — the axes. Pins that the knob does what it claims: field is value-blind, clause is value-aware,
polarity signs the tokens (+ selection, - filter), fieldref and logsource become tags, and — the essay's
whole point — value-aware separates rules that value-blind collapses."""

from omega.axes import CONTENT, FIELD_SET, attributes
from omega.ingest.sigma import load, to_ir

_TWO_RULES = """\
title: A
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\a.exe'
  filter_main:
    User|contains: 'system'
  condition: selection and not 1 of filter_*
---
title: B
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\b.exe'
  condition: selection
"""


def _irs(tmp_path):
    (tmp_path / "r.yml").write_text(_TWO_RULES)
    rules, _ = load(tmp_path)
    return {r.title: to_ir(r) for r in rules}


def test_field_is_value_blind_clause_is_value_aware(tmp_path):
    a = _irs(tmp_path)["A"]
    field = attributes(a, axes={"field"})
    clause = attributes(a, axes={"clause"})
    assert field == {"field:Image", "field:User"}                       # values thrown away
    assert "clause:Image|endswith=*\\a.exe" in clause                    # value kept
    assert "clause:User|contains=*system*" in clause                     # pySigma bakes the contains wildcards in


def test_polarity_signs_selection_and_filter(tmp_path):
    a = _irs(tmp_path)["A"]
    signed = attributes(a, axes={"clause", "polarity"})
    assert "+clause:Image|endswith=*\\a.exe" in signed                   # selection -> +
    assert "-clause:User|contains=*system*" in signed                   # filter    -> -


def test_logsource_and_attack_are_tags(tmp_path):
    a = _irs(tmp_path)["A"]
    ls = attributes(a, axes={"logsource"})
    assert ls == {"product:windows", "category:process_creation"}


def test_value_aware_separates_what_value_blind_collapses(tmp_path):
    irs = _irs(tmp_path)
    a, b = irs["A"], irs["B"]
    # value-BLIND: A reads {Image, User} (User via its filter), B reads {Image} -> distinguishable HERE only
    # because A has a filter B lacks; the load-bearing point is the value-aware case below.
    assert attributes(a, axes=FIELD_SET) == {"field:Image", "field:User"}
    assert attributes(b, axes=FIELD_SET) == {"field:Image"}
    # value-AWARE: distinct by the Image VALUE (a.exe vs b.exe) even ignoring the filter -> the real fix
    assert attributes(a, axes=CONTENT) != attributes(b, axes=CONTENT)


def test_presets_are_pure_logic(tmp_path):
    """Presets carry no logsource — sameness defaults to logic; context (product/category) is opt-in."""
    a = _irs(tmp_path)["A"]
    assert not any(tok.startswith(("product:", "category:")) for tok in attributes(a, axes=CONTENT))
    assert not any(tok.startswith(("product:", "category:")) for tok in attributes(a, axes=FIELD_SET))
    # adding the logsource axis refines: the product/category tags appear
    refined = attributes(a, axes=CONTENT | {"logsource"})
    assert "product:windows" in refined and "category:process_creation" in refined
