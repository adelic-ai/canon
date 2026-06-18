"""Sigma glob matching — proper wildcards, checked conclusively.

Two layers of verification (design/detection_ir_semantics.md, wildcards clause):

* **Conclusive core** — :func:`test_glob_agrees_with_fnmatch_exhaustively` enumerates *every* pattern/string
  pair over a bounded alphabet and asserts our matcher agrees with Python's stdlib ``fnmatchcase`` — an
  INDEPENDENT glob engine. Exhaustive over the domain ⇒ the ``*``/``?`` semantics are verified against an
  outside implementation, not our own re-derivation. (pySigma would be the domain oracle but is not an event
  matcher — it converts rules to queries; ``fnmatch`` is the executable glob reference.)
* **Golden table** — the Sigma escape/metacharacter edges ``fnmatch`` cannot express (``\\*`` literal star,
  literal ``.``/``+`` in values, backslash paths, the modifiers), hand-verified against the Sigma spec.
"""

import fnmatch
import itertools

from detection.sigma_eval import field_matches, glob_regex_body, has_wildcard


def test_glob_agrees_with_fnmatch_exhaustively():
    """Exhaustive differential vs an independent glob engine — the conclusive accuracy check."""
    pat_alphabet, str_alphabet = "ab*?", "ab"
    checked = 0
    for plen in range(0, 5):
        for pat in map("".join, itertools.product(pat_alphabet, repeat=plen)):
            for slen in range(0, 5):
                for s in map("".join, itertools.product(str_alphabet, repeat=slen)):
                    ours = field_matches(s, pat, set())          # eq-mode = full glob match
                    ref = fnmatch.fnmatchcase(s, pat)            # independent reference
                    assert ours == ref, (pat, s, ours, ref)
                    checked += 1
    assert checked > 5000                                        # ~10.5k pairs, exhaustive over the domain


GOLDEN = [
    # the real wildcard case that was a false gap under literal matching
    ("python3*.dll+", {"contains"}, "...python311.dll+0x1234...", True),
    ("python3*.dll+", {"contains"}, "...python27.dll+...", False),       # 'python3' prefix required
    # regex metacharacters in the value are LITERAL, not regex (the naive .replace bug)
    ("comsvcs.dll", {"contains"}, "x\\comsvcs.dll+0x1", True),
    ("comsvcs.dll", {"contains"}, "x\\comsvcsXdll+0x1", False),          # the '.' is literal
    ("lsass.exe+", {"contains"}, "y lsass.exe+ z", True),                # the '+' is literal
    ("lsass.exe+", {"contains"}, "y lsass.exeXX z", False),
    # endswith / startswith with backslash paths (literal backslashes)
    ("\\lsass.exe", {"endswith"}, "C:\\Windows\\System32\\lsass.exe", True),
    ("\\lsass.exe", {"endswith"}, "C:\\Windows\\System32\\lsassZexe", False),
    ("C:\\Users\\foo", {"startswith"}, "c:\\users\\foo\\bar.txt", True),
    # bare and embedded wildcards
    ("*", set(), "anything at all", True),
    ("a?c", set(), "abc", True),
    ("a?c", set(), "ac", False),                                         # ? = exactly one char
    ("a?c", set(), "abbc", False),
    # Sigma escape: \* is a LITERAL asterisk, not a wildcard
    ("\\*box", set(), "*box", True),
    ("\\*box", set(), "Xbox", False),
]


def test_golden_sigma_cases():
    for pat, mods, inp, expected in GOLDEN:
        assert field_matches(inp, pat, mods) is expected, (pat, mods, inp)


def test_nonwildcard_is_unchanged_substring_semantics():
    # why the change is non-regressive on real rules: no-wildcard contains is still plain substring,
    # and endswith is still plain suffix (ASCII case-insensitive)
    assert field_matches("xx comsvcs.dll yy", "comsvcs.dll", {"contains"})
    assert not field_matches("xx comsvcs yy", "comsvcs.dll", {"contains"})
    assert field_matches("C:\\X\\RUNDLL32.EXE", "\\rundll32.exe", {"endswith"})


def test_has_wildcard_detects_only_unescaped():
    assert has_wildcard("python3*.dll")
    assert has_wildcard("a?b")
    assert not has_wildcard("comsvcs.dll")
    assert not has_wildcard("\\*literal")          # escaped → not a wildcard
    assert not has_wildcard("plain\\path")


def test_glob_regex_body_is_the_shared_definition():
    # the single regex source the emitters share; modifiers are glob sugar
    assert glob_regex_body("x", "contains") == ".*x.*"
    assert glob_regex_body("x", "startswith") == "x.*"
    assert glob_regex_body("x", "endswith") == ".*x"
    assert glob_regex_body("py*.dll", "eq") == "py.*\\.dll"      # * → .* , literal '.' escaped
