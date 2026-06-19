"""The atom→TTP inverted index — signed membership, specificity (IDF), routing."""

from pathlib import Path

import pytest

from detection.atom_index import (
    block_polarities,
    build_atom_index,
    candidate_techniques,
    specificity,
    techniques_for,
)
from detection.atoms import clause_atom_id
from detection.rule_ir import compile_rule
from detection.sigma_panel import SIGMA

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"

# the SAME rundll32 atom appears in two rules under two techniques — once as a selector, once where the
# rule also has a filter (the filter's atom is a negative/exclusion participation)
_R_SEL = {"id": "a", "tags": ["attack.t1003.001"],
          "detection": {"selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "selection"}}
_R_FILTER = {"id": "b", "tags": ["attack.t1218.011"],
             "detection": {"selection": {"Image|endswith": "\\rundll32.exe"},
                           "filter": {"CommandLine|contains": "benign"},
                           "condition": "selection and not filter"}}


def _rundll32_atom():
    ir = compile_rule(_R_SEL)
    return clause_atom_id(next(c for b in ir.blocks for m in b.maps for c in m))


def _benign_atom():
    ir = compile_rule(_R_FILTER)
    return clause_atom_id(next(c for b in ir.blocks for m in b.maps for c in m if c.field == "CommandLine"))


def test_block_polarities_signs_selectors_and_filters():
    pol = block_polarities(compile_rule(_R_FILTER))
    assert pol["selection"] == {1}          # positive selector
    assert pol["filter"] == {-1}            # under `not` → exclusion


def test_quantifier_patterns_expand_to_block_names():
    rule = {"id": "q", "tags": ["attack.t1059"],
            "detection": {"sel_a": {"A|contains": "x"}, "sel_b": {"B|contains": "y"},
                          "filt_1": {"C|contains": "z"},
                          "condition": "1 of sel_* and not 1 of filt_*"}}
    pol = block_polarities(compile_rule(rule))
    assert pol["sel_a"] == {1} and pol["sel_b"] == {1}    # `1 of sel_*` → positive
    assert pol["filt_1"] == {-1}                          # `not 1 of filt_*` → negative


def test_atom_carries_signed_ttp_set():
    idx = build_atom_index([_R_SEL, _R_FILTER])
    rundll32, benign = _rundll32_atom(), _benign_atom()
    # the shared rundll32 atom participates POSITIVELY in both techniques
    assert techniques_for(idx, rundll32) == {"T1003.001": [1], "T1218.011": [1]}
    # the filter atom participates NEGATIVELY in T1218.011 (an exclusion, not evidence-for)
    assert techniques_for(idx, benign) == {"T1218.011": [-1]}


def test_specificity_is_the_ttp_spread():
    idx = build_atom_index([_R_SEL, _R_FILTER])
    # rundll32 spans 2 techniques (generic, weak); the benign filter atom 1 (here, exclusion-only)
    assert specificity(idx, _rundll32_atom()) == 2
    assert specificity(idx, _benign_atom()) == 1


def test_candidate_techniques_routes_on_positive_participation_only():
    idx = build_atom_index([_R_SEL, _R_FILTER])
    # firing rundll32 nominates both techniques (positive in both)
    assert candidate_techniques(idx, [_rundll32_atom()]) == {"T1003.001", "T1218.011"}
    # firing only the benign filter atom nominates NOTHING (its participation is negative)
    assert candidate_techniques(idx, [_benign_atom()]) == set()


def test_rules_without_attack_tags_are_skipped():
    idx = build_atom_index([{"id": "x", "detection": {"selection": {"Image|endswith": "\\x.exe"},
                                                      "condition": "selection"}}])
    assert idx == {}


@pytest.mark.skipif(not SIGMA.exists(), reason="SigmaHQ rules not present")
def test_idf_generic_vs_discriminating_on_real_corpus():
    """On real rules across many techniques, a generic atom (rundll32) participates in MORE TTPs than a
    near-exclusive discriminator — specificity is the IDF signal."""
    from detection.sigma_panel import gather
    rules = [r for t in ("T1003.001", "T1218.011", "T1059.001", "T1055")
             for _p, r in gather(t, root=SIGMA)]
    idx = build_atom_index(rules)
    # the index is non-trivial and specificity varies (some atoms are generic, some near-exclusive)
    spreads = sorted(specificity(idx, a) for a in idx)
    assert idx and spreads[0] == 1 and spreads[-1] > 1       # both discriminators and generic atoms exist
