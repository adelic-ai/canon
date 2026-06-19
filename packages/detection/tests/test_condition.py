"""Sigma condition parser + evaluator — general boolean conditions over named blocks."""

import pytest

from detection.condition import condition_parses, eval_condition, parse_condition


def test_parses_supported_grammar_rejects_aggregation():
    for ok in ["selection", "selection and not 1 of filter*", "sel_a and sel_b or sel_c",
               "all of selection_*", "1 of them", "(a or b) and not c", "not filter", "2 of selection_*"]:
        assert condition_parses(ok), ok
    for bad in ["selection | count() by x > 5", "selection and", "of them", "1 of", ")", "a b"]:
        assert not condition_parses(bad), bad


def test_named_blocks_and_boolean():
    det = {
        "sel_img": {"Image|endswith": "\\rundll32.exe"},
        "sel_cmd": {"CommandLine|contains": "comsvcs"},
        "condition": "sel_img and sel_cmd",
    }
    assert eval_condition(det, {"Image": "C:\\X\\rundll32.exe", "CommandLine": "x comsvcs y"}) is True
    assert eval_condition(det, {"Image": "C:\\X\\rundll32.exe", "CommandLine": "nope"}) is False


def test_quantifier_one_of_glob():
    det = {
        "selection_a": {"A|contains": "x"},
        "selection_b": {"B|contains": "y"},
        "condition": "1 of selection_*",
    }
    assert eval_condition(det, {"A": "x"}) is True          # one matches
    assert eval_condition(det, {"B": "y"}) is True
    assert eval_condition(det, {"C": "z"}) is False         # none match


def test_quantifier_all_of_them_and_not_filter():
    det = {
        "selection": {"Image|endswith": "\\lsass.exe"},
        "filter_legit": {"User|contains": "SYSTEM"},
        "condition": "selection and not 1 of filter*",
    }
    assert eval_condition(det, {"Image": "x\\lsass.exe", "User": "alice"}) is True
    assert eval_condition(det, {"Image": "x\\lsass.exe", "User": "NT SYSTEM"}) is False   # suppressed


def test_list_block_is_or_of_maps():
    det = {"selection": [{"Image|endswith": "\\a.exe"}, {"Image|endswith": "\\b.exe"}],
           "condition": "selection"}
    assert eval_condition(det, {"Image": "x\\b.exe"}) is True
    assert eval_condition(det, {"Image": "x\\c.exe"}) is False


def test_precedence_not_binds_tighter_than_and_or():
    # "a or not b and c"  ==  a or ((not b) and c)
    ast = parse_condition("a or not b and c")
    assert ast == ("or", [("ref", "a"), ("and", [("not", ("ref", "b")), ("ref", "c")])])
