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


# --- regression: glob/transform soundness + derive-preserves-False + hex numerics (review HIGH) ---

def test_glob_value_does_not_falsely_exclude():
    # EventID|equals "1*" is a glob that MATCHES "10" → the two are NOT mutually exclusive.
    assert not excludes(_c("EventID", ["equals"], "1*"), _c("EventID", ["equals"], "10"))
    # but genuine distinct literals still exclude
    assert excludes(_c("EventID", ["equals"], "4624"), _c("EventID", ["equals"], "4625"))


def test_transforming_modifier_is_opaque_to_exclusion():
    assert not excludes(_c("CommandLine", ["windash"], "-s"), _c("CommandLine", ["equals"], "-s"))


def test_glob_implication_is_withheld_unless_identical():
    assert not implies(_c("Image", ["contains"], "a*b"), _c("Image", ["contains"], "ab"))
    assert implies(_c("Image", ["contains"], "a*b"), _c("Image", ["contains"], "a*b"))   # identical ok


def test_derive_preserves_an_observed_false():
    # 0 ⟹ 1, observed {0:True, 1:False} is a contradiction — derive must NOT overwrite 1 to True.
    out = derive({0: True, 1: False}, [(0, 1)])
    assert out[1] is False
    assert consistency_violations({0: True, 1: False}, [(0, 1)], []) == [
        {"kind": "implication", "a": 0, "b": 1}]
    # but an ABSENT atom is still filled
    assert derive({0: True}, [(0, 1)])[1] is True


def test_hex_numeric_implication_grantedaccess():
    # GrantedAccess masks are hex; gt 0x1000 ⟹ gte 0x1000
    assert implies(_c("GrantedAccess", ["gt"], "0x1000"), _c("GrantedAccess", ["gte"], "0x1000"))
    assert implies(_c("GrantedAccess", ["gte"], "0x1410"), _c("GrantedAccess", ["gte"], "0x1000"))
