"""Stage 2 — the axes. Pins that the knob does what it claims: field is value-blind, clause is value-aware,
polarity signs the tokens (+ selection, - filter), fieldref and logsource become tags, and — the essay's
whole point — value-aware separates rules that value-blind collapses."""

from omega.axes import CONTENT, FIELD_SET, attributes
from omega.ingest.sigma import load, to_ir
from omega.ir import Atom, Block, CompiledRule


def _rule(*atoms, polarity=1):
    """A one-block rule from raw atoms — exercises the projection layer in isolation."""
    return CompiledRule(id="x", title="x", logsource=(), tags=(),
                        blocks=(Block(name="selection", polarity=polarity, atoms=tuple(atoms)),),
                        condition="selection")

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


def test_atlas_axis_reads_direct_tag_only():
    """ATLAS-SPEC.md §3.2: the axis handles DIRECT rule->ATLAS tagging only (rare today); the transitive
    bridge through attack tokens is a corpus-level concern, not a per-rule projection (omega.coverage)."""
    direct = CompiledRule(id="x", title="x", logsource=(), tags=("atlas.aml.t0043", "attack.t1059"),
                          blocks=(), condition="")
    assert attributes(direct, axes={"atlas"}) == {"atlas:AML.T0043"}
    # a plain attack tag, with no atlas.-prefixed tag, contributes nothing to the atlas axis
    bridge_only = CompiledRule(id="y", title="y", logsource=(), tags=("attack.t1059",),
                               blocks=(), condition="")
    assert attributes(bridge_only, axes={"atlas"}) == set()


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


# ── regression pins for the projection-layer fixes ──────────────────────────────────────────────────

def test_fieldreference_atom_still_reads_its_field():
    """#1: a field read via field-reference must not vanish from the value-blind projection."""
    fr     = Atom(field="SourceImage", mods=("fieldreference",), values=("ParentImage",))
    normal = Atom(field="TargetImage", mods=("endswith",), values=("\\a.exe",))
    ir = _rule(fr, normal)

    field = attributes(ir, axes=FIELD_SET)
    assert "field:SourceImage" in field          # was dropped by the early `continue`
    assert "field:TargetImage" in field

    # the relational token is an ADDITION under the fieldref axis, not a replacement
    both = attributes(ir, axes={"field", "fieldref"})
    assert "field:SourceImage" in both
    assert "fieldref:SourceImage~ParentImage" in both

    # and it no longer vanishes from the value-aware projection either
    assert any(t.startswith("clause:SourceImage|") for t in attributes(ir, axes={"clause"}))


def test_clause_comma_value_does_not_collide_with_two_values():
    """#2a: one value containing a comma must not equal two separate values."""
    one = _rule(Atom(field="CommandLine", mods=(), values=("a,b",)))
    two = _rule(Atom(field="CommandLine", mods=(), values=("a", "b")))
    assert attributes(one, axes={"clause"}) != attributes(two, axes={"clause"})


def test_clause_is_invariant_to_value_order():
    """#2b: a value list is an unordered OR — the token must not depend on author ordering."""
    ab = _rule(Atom(field="Image", mods=("contains",), values=("cmd", "powershell")))
    ba = _rule(Atom(field="Image", mods=("contains",), values=("powershell", "cmd")))
    assert attributes(ab, axes={"clause"}) == attributes(ba, axes={"clause"})


def test_clause_keeps_mods_ordered():
    """Chained modifiers are sequential — base64|contains must NOT equal contains|base64."""
    a = _rule(Atom(field="CommandLine", mods=("base64", "contains"), values=("x",)))
    b = _rule(Atom(field="CommandLine", mods=("contains", "base64"), values=("x",)))
    assert attributes(a, axes={"clause"}) != attributes(b, axes={"clause"})
