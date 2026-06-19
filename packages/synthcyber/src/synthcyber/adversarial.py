"""Adversarial semantics corpus — correct-by-construction ``(rule, event, expected)`` cases that stress each
landmine of a detection evaluator's string-semantics (ASCII vs non-ASCII case, glob wildcards, regex-meta
literals, escaped wildcards, missing/empty fields, coercion, multibyte UTF-8).

Pure data — no dependency on canon. The CONSUMER (``detection.adversarial.attest_corpus``, which runs the
emitters and checks agreement) lives in canon; this only declares the labeled cases.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdversarialCase:
    """One correct-by-construction case: a single-clause Sigma rule, an event, and the match a *pinned* ASCII /
    Sigma-glob semantics profile must produce. ``landmine`` names the semantic it stresses."""

    landmine: str
    rule: dict
    event: dict
    expected: bool
    note: str = ""


def _rule(key: str, value) -> dict:
    """A minimal evaluable Sigma rule: one selection clause, ``condition: selection``."""
    return {"id": f"adv-{key}", "detection": {"selection": {key: value}, "condition": "selection"}}


def adversarial_corpus() -> list[AdversarialCase]:
    """The labeled adversarial panel. Each ``expected`` follows the pinned profile, not intuition — e.g.
    non-ASCII case is NOT folded, so ``RENÉ`` does not match ``rené``."""
    C = AdversarialCase
    return [
        C("ascii_case", _rule("TargetImage|endswith", "\\lsass.exe"),
          {"TargetImage": "C:\\X\\LSASS.EXE"}, True, "ASCII fold: LSASS.EXE ~ \\lsass.exe"),
        C("nonascii_case", _rule("User|eq", "rené"),
          {"User": "RENÉ"}, False, "ASCII pin does NOT fold É — both emitters agree (no match)"),
        C("nonascii_exact", _rule("User|eq", "café"),
          {"User": "café"}, True, "exact non-ASCII, already lowercase → no fold needed"),
        C("wildcard", _rule("CallTrace|contains", "python3*.dll+"),
          {"CallTrace": "x python311.dll+ y"}, True, "* absorbs '11'"),
        C("literal_metachar", _rule("CallTrace|contains", "comsvcs.dll"),
          {"CallTrace": "x comsvcsXdll y"}, False, "the '.' is a literal, not regex any-char"),
        C("escaped_wildcard", _rule("Cmd|eq", "\\*flag"),
          {"Cmd": "*flag"}, True, "\\* is a literal asterisk"),
        C("missing_field", _rule("CallTrace|endswith", "comsvcs.dll"),
          {"TargetImage": "x"}, False, "an absent referenced field defaults to empty → no match"),
        C("empty_pattern", _rule("TargetImage|endswith", ""),
          {"TargetImage": "anything"}, True, "endswith empty is vacuously true"),
        C("bool_value", _rule("Success|eq", "true"),
          {"Success": True}, True, "bool coerces via str()→'True'→ascii-lower 'true'"),
        C("numeric_value", _rule("EventID|eq", "4624"),
          {"EventID": 4624}, True, "int coerces to its decimal string"),
        C("utf8_substring", _rule("Path|contains", "日本"),
          {"Path": "x 日本 y"}, True, "caseless multibyte UTF-8 substring"),
    ]
