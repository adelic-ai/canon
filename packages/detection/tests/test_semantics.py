"""IR semantics profile — pin the case-fold contract (design/detection_ir_semantics.md).

These tests fix the *deliberate* decision: the IR folds ASCII case only. Full-Unicode `.lower()` is a
language default, not the spec — pinning it here stops an emitter (or a refactor) from silently reintroducing
Unicode folding, which would make Python and a byte-folding Rust emitter disagree off-ASCII.
"""

from detection.sigma_eval import _ascii_lower, field_matches


def test_ascii_lower_folds_only_ascii():
    assert _ascii_lower("ABC.dll") == "abc.dll"
    assert _ascii_lower("C:\\Windows\\LSASS.exe") == "c:\\windows\\lsass.exe"
    # the pinned trade-off: non-ASCII case is NOT folded (str.lower() would fold these)
    assert _ascii_lower("É") == "É" != "É".lower()
    assert _ascii_lower("İ") == "İ"


def test_ascii_lower_equals_str_lower_on_ascii():
    # why the change is non-regressive on real rules: identical to str.lower() for ASCII
    for s in ("\\lsass.exe", "RUNDLL32.EXE", "comsvcs.DLL", "0x1FFFFF", "Python311.dll+"):
        assert _ascii_lower(s) == s.lower()


def test_field_matches_is_ascii_case_insensitive():
    assert field_matches("C:\\X\\LSASS.EXE", "\\lsass.exe", {"endswith"})   # ASCII case-insensitive
    assert field_matches("é", "é", set())                                   # exact match holds
    assert not field_matches("É", "é", set())                               # but ASCII pin does NOT fold É→é
