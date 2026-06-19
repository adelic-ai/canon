"""Rust emitter — the native IR interpreter must agree with the Python oracle (eval_ir). Gated on the built
``motif-rs`` binary (built out-of-tree); skips when absent, like the corpus-gated tests."""

from pathlib import Path

import pytest

from detection.rust_emitter import attest_rust_agreement, eval_rust, rust_available
from detection.sigma_panel import SIGMA, gather

pytestmark = pytest.mark.skipif(not rust_available(), reason="motif-rs binary not built")


def _rule(detection):
    return {"id": "r", "detection": detection}


CRAFTED = [
    _rule({"selection": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "selection"}),
    _rule({"s1": {"Image|endswith": "\\rundll32.exe"}, "s2": {"CommandLine|contains": "comsvcs"},
           "condition": "s1 and s2"}),
    _rule({"sel_a": {"A|contains": "x"}, "sel_b": {"B|contains": "y"}, "condition": "1 of sel_*"}),
    _rule({"keywords": ["mimikatz", "sekurlsa"], "condition": "keywords"}),
    _rule({"selection": {"CallTrace|contains": "python3*.dll+"}, "condition": "selection"}),
    _rule({"selection": {"Image|endswith": "\\lsass.exe"}, "filter": {"User|contains": "SYSTEM"},
           "condition": "selection and not 1 of filter*"}),
]
EVENTS = [
    {"TargetImage": "C:\\X\\LSASS.EXE", "Image": "C:\\W\\rundll32.exe", "CommandLine": "x comsvcs y"},
    {"A": "x"}, {"B": "y"}, {"C": "z"}, {"CallTrace": "p python311.dll+ q"},
    {"CommandLine": "run mimikatz sekurlsa::logonpasswords"},
    {"Image": "C:\\X\\lsass.exe", "User": "NT SYSTEM"}, {"Image": "C:\\X\\lsass.exe", "User": "alice"}, {},
]


def test_rust_matches_oracle_on_crafted_constructs():
    rep = attest_rust_agreement(CRAFTED, EVENTS)
    assert rep["faithful"], rep["disagreements"][:5]
    assert rep["n_supported"] >= 5               # the glob/string/keyword/condition core is handled
    assert rep["checked"] > 0


def test_rust_actually_fires_and_abstains_honestly():
    from detection.rule_ir import compile_rule
    # a supported rule fires; an unsupported-modifier rule is marked unsupported (not silently wrong)
    rules = [compile_rule(CRAFTED[0]),
             compile_rule(_rule({"selection": {"CommandLine|re": "-enc"}, "condition": "selection"}))]
    results, supported = eval_rust(rules, EVENTS)
    assert supported[0] is True and supported[1] is False        # |re abstains in Rust (for now)
    assert results[0][0] is True                                 # lsass.exe endswith fires


@pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")
def test_rust_faithful_across_real_rules():
    from detection.sigma_eval import is_evaluable
    rules = [r for _, r in gather("T1003.001") if is_evaluable(r)]
    rep = attest_rust_agreement(rules, EVENTS)
    assert rep["faithful"], rep["disagreements"][:5]
    assert rep["n_rules"] >= 20 and rep["n_supported"] >= 10     # most real rules are Rust-handled
