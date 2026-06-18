"""Adversarial semantics corpus — the first concrete dataset-generator slice (design/dataset_generator_product.md),
focused on the IR semantics gate (design/detection_ir_semantics.md).

OTRF is the ASCII happy path; it exercises almost none of the semantics profile. This generates
**correct-by-construction** ``(rule, event, expected)`` cases that stress each landmine — ASCII vs non-ASCII
case-fold, glob wildcards, regex-metacharacter literals, escaped wildcards, missing/empty fields, non-string
coercion, multibyte UTF-8 — and attests two things over the panel at once:

* **correctness** — the Python oracle computes the by-construction ``expected`` (the *pinned* spec, e.g. the
  ASCII fold does **not** fold ``É``→``é``);
* **parity** — the Python and SPARQL emitters agree.

This is where the generator earns its keep: it turns the spec's "open items" into an executable, *localized*
conformance report. It first surfaced a SPARQL escape-routing bug (``\\*``) and a Unicode-``LCASE`` residual on
``nonascii_case`` — both since fixed (the SPARQL emitter now pre-folds event values ASCII-only, exactly like the
oracle), so the panel now reports **full parity** across every landmine; the report would re-localize any future
divergence. (Correct-by-construction labels are the dataset-generator's core value, applied to the emitter gate.)
"""

from __future__ import annotations

from dataclasses import dataclass

from detection.fidelity import _cid
from detection.motif import eval_python, eval_sparql, from_sigma


@dataclass(frozen=True)
class AdversarialCase:
    """One correct-by-construction case: a single-clause Sigma rule, an event, and the match the *pinned*
    semantics profile must produce. ``landmine`` names the semantic it stresses."""

    landmine: str
    rule: dict
    event: dict
    expected: bool
    note: str = ""


def _rule(key: str, value) -> dict:
    """A minimal evaluable Sigma rule: one selection clause, ``condition: selection``."""
    return {"id": f"adv-{key}", "detection": {"selection": {key: value}, "condition": "selection"}}


def adversarial_corpus() -> list[AdversarialCase]:
    """The labeled adversarial panel. Each ``expected`` follows the *pinned* profile, not intuition — e.g.
    non-ASCII case is NOT folded, so ``RENÉ`` does not match ``rené``."""
    C = AdversarialCase
    return [
        C("ascii_case", _rule("TargetImage|endswith", "\\lsass.exe"),
          {"TargetImage": "C:\\X\\LSASS.EXE"}, True, "ASCII fold: LSASS.EXE ~ \\lsass.exe"),
        # ASCII pin does not fold É→é → no match. Both emitters now agree here (SPARQL pre-folds ASCII-only,
        # like the oracle); this case formerly localized the Unicode-LCASE residual, now closed.
        C("nonascii_case", _rule("User|eq", "rené"),
          {"User": "RENÉ"}, False, "ASCII pin does NOT fold É — both emitters agree (no match)"),
        C("nonascii_exact", _rule("User|eq", "café"),
          {"User": "café"}, True, "exact non-ASCII, already lowercase → no fold needed, both agree"),
        C("wildcard", _rule("CallTrace|contains", "python3*.dll+"),
          {"CallTrace": "x python311.dll+ y"}, True, "* absorbs '11'"),
        C("literal_metachar", _rule("CallTrace|contains", "comsvcs.dll"),
          {"CallTrace": "x comsvcsXdll y"}, False, "the '.' is a literal, not regex any-char"),
        C("escaped_wildcard", _rule("Cmd|eq", "\\*flag"),
          {"Cmd": "*flag"}, True, "\\* is a literal asterisk (this case found the SPARQL escape-routing bug)"),
        C("missing_field", _rule("CallTrace|endswith", "comsvcs.dll"),
          {"TargetImage": "x"}, False, "an absent referenced field defaults to empty → no match"),
        C("empty_pattern", _rule("TargetImage|endswith", ""),
          {"TargetImage": "anything"}, True, "endswith empty is vacuously true"),
        C("bool_value", _rule("Success|eq", "true"),
          {"Success": True}, True, "bool coerces via str()→'True'→ascii-lower 'true' (Rust coercion latent)"),
        C("numeric_value", _rule("EventID|eq", "4624"),
          {"EventID": 4624}, True, "int coerces to its decimal string"),
        C("utf8_substring", _rule("Path|contains", "日本"),
          {"Path": "x 日本 y"}, True, "caseless multibyte UTF-8 substring (no fold involved)"),
    ]


def attest_corpus(cases: list[AdversarialCase] | None = None) -> dict:
    """Run both emitters over the corpus; report **correctness** (oracle == expected) and **parity**
    (python == sparql) per case, grouped/localized by landmine. Content-addressed so the conformance claim
    re-derives. ``incorrect`` should be empty (the oracle conforms to the pinned spec); ``divergent`` should
    be exactly the documented residual(s)."""
    cases = cases if cases is not None else adversarial_corpus()
    rows, incorrect, divergent = [], [], []
    for c in cases:
        g = from_sigma(c.rule)
        py = eval_python(g, c.event)
        sp = eval_sparql(g, c.event)
        row = {"landmine": c.landmine, "expected": c.expected, "python": py, "sparql": sp,
               "correct": py == c.expected, "agree": py == sp}
        rows.append(row)
        if not row["correct"]:
            incorrect.append(row)
        if not row["agree"]:
            divergent.append(row)
    body = {"n": len(cases), "rows": rows}
    return {
        "n": len(cases),
        "oracle_correct": not incorrect,
        "emitters_agree": not divergent,
        "incorrect": incorrect,                       # oracle ≠ pinned spec — a real bug if non-empty
        "divergent": divergent,                       # python ≠ sparql — should be the documented residual only
        "divergent_landmines": sorted({r["landmine"] for r in divergent}),
        "by_landmine": {r["landmine"]: r for r in rows},
        "cid": _cid(body),
    }
