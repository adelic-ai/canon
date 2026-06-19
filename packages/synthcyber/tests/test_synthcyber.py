"""synthcyber — the standalone generator: labeled scenarios, adversarial cases, reproducible recipes, and the
boundary (no canon imports)."""

import inspect

from synthcyber import (
    AdversarialCase,
    Scenario,
    adversarial_corpus,
    compose,
    recipe_cid,
    scenario_positives,
    t1003_001_scenarios,
)


def test_scenarios_are_labeled_and_multichannel():
    sc = t1003_001_scenarios()
    assert len(sc) >= 5
    assert {s.channel for s in sc} >= {"process_access", "file_event", "registry"}
    assert all(isinstance(s, Scenario) and s.technique == "T1003.001" and s.events for s in sc)
    assert len(scenario_positives(sc)) >= len(sc)


def test_adversarial_corpus_is_labeled():
    cases = adversarial_corpus()
    assert len(cases) >= 8
    assert {c.expected for c in cases} == {True, False}
    assert all(isinstance(c, AdversarialCase) and c.rule and c.event for c in cases)


def test_recipe_cid_is_deterministic_and_structural():
    a, b = t1003_001_scenarios(), t1003_001_scenarios()
    assert recipe_cid(a) == recipe_cid(b) and len(recipe_cid(a)) == 64   # reproducible
    assert recipe_cid(a) != recipe_cid(a[:2])                            # different corpus → different CID


def test_compose_merges():
    sc = t1003_001_scenarios()
    assert len(compose(sc, sc)) == 2 * len(sc)


def test_generator_does_not_import_canon():
    """The boundary, enforced: the generator depends on NOTHING from canon."""
    import synthcyber.adversarial
    import synthcyber.recipe
    import synthcyber.scenarios
    for m in (synthcyber.scenarios, synthcyber.adversarial, synthcyber.recipe):
        src = inspect.getsource(m)
        for forbidden in ("import detection", "from detection", "forge_core", "provenance"):
            assert forbidden not in src, f"{m.__name__} imports canon: {forbidden}"
