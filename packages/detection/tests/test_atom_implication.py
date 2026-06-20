"""The atom-implication lattice — predicate implication, exclusion, derivation, and the soundness check."""

from detection.atom_implication import (
    build_atom_implications,
    consistency_violations,
    derive,
    excludes,
    implies,
)
from detection.rule_ir import Clause


def _c(field, mods, value):
    return Clause(field, tuple(mods), (value,))


def test_string_op_implications():
    # stricter op ⟹ looser op (same substring)
    assert implies(_c("Image", ["endswith"], "\\rundll32.exe"), _c("Image", ["contains"], "rundll32.exe"))
    assert implies(_c("Image", ["equals"], "C:\\X\\rundll32.exe"), _c("Image", ["endswith"], "rundll32.exe"))
    # superstring contains ⟹ substring contains
    assert implies(_c("CommandLine", ["contains"], "comsvcs.dll MiniDump"),
                   _c("CommandLine", ["contains"], "comsvcs"))
    # case-insensitive (Sigma)
    assert implies(_c("Image", ["endswith"], "\\RUNDLL32.EXE"), _c("Image", ["contains"], "rundll32"))
    # NOT: contains does not imply endswith
    assert not implies(_c("Image", ["contains"], "rundll32"), _c("Image", ["endswith"], "rundll32"))
    # different fields never imply
    assert not implies(_c("Image", ["contains"], "x"), _c("CommandLine", ["contains"], "x"))


def test_numeric_implications():
    assert implies(_c("Size", ["gt"], "100"), _c("Size", ["gte"], "100"))   # >100 ⟹ >=100
    assert implies(_c("Size", ["gte"], "200"), _c("Size", ["gte"], "100"))  # >=200 ⟹ >=100
    assert not implies(_c("Size", ["gte"], "100"), _c("Size", ["gte"], "200"))


def test_exclusion_is_same_field_distinct_equals():
    assert excludes(_c("EventID", [], "10"), _c("EventID", [], "1"))        # a field can't equal both
    assert not excludes(_c("EventID", [], "10"), _c("EventID", [], "10"))   # same value: not exclusive
    assert not excludes(_c("EventID", [], "10"), _c("Other", [], "1"))      # different field


def test_build_finds_generators_and_derivable_atoms():
    atoms = [_c("Image", ["endswith"], "\\rundll32.exe"),   # 0 — generator (implies 1)
             _c("Image", ["contains"], "rundll32"),          # 1 — implied by 0 (derivable)
             _c("CommandLine", ["contains"], "comsvcs")]     # 2 — generator (its own field)
    res = build_atom_implications(atoms)
    assert (0, 1) in res["implications"]
    assert set(res["generators"]) == {0, 2}                  # 1 is implied → not a generator
    # derive: evaluating only the generators, atom 1 is True wherever atom 0 fired
    full = derive({0: True, 2: False}, res["implications"])
    assert full[1] is True                                   # derived, never evaluated


def test_consistency_violation_is_a_contradiction():
    atoms = [_c("Image", ["endswith"], "\\rundll32.exe"), _c("Image", ["contains"], "rundll32")]
    impl = build_atom_implications(atoms)
    # endswith True but contains False is impossible → flagged (a Belnap Both / soundness alarm)
    bad = consistency_violations({0: True, 1: False}, impl["implications"], impl["exclusions"])
    assert len(bad) == 1 and bad[0]["kind"] == "implication"
    # a consistent assignment flags nothing
    assert consistency_violations({0: True, 1: True}, impl["implications"], impl["exclusions"]) == []


def test_exclusion_violation_flags_both_true():
    atoms = [_c("EventID", [], "10"), _c("EventID", [], "1")]
    impl = build_atom_implications(atoms)
    bad = consistency_violations({0: True, 1: True}, impl["implications"], impl["exclusions"])
    assert len(bad) == 1 and bad[0]["kind"] == "exclusion"
