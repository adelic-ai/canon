"""synthcyber — a standalone generator of synthetic, correct-by-construction labeled cyber datasets.

Data PRODUCTION lives here; it depends on nothing from canon (the engine/workspace boundary —
``design/engine_workspace_boundary.md``: data-in = workspace, data-out = generator, both outside the engine).
canon is **one consumer**: it imports these scenarios/cases and runs its detectors over them (the consumers —
``variant_coverage``, ``attest_corpus``, ``technique_fidelity`` — stay in canon). Labels are correct-by-
construction (the generator placed the malicious events), and a recipe CID makes a generated corpus a
reproducible, citable artifact.

This is the first extraction — the existing fidelity/semantics corpora consolidated under one home, minus the
layer-2 product (difficulty/realism knobs, OCSF serializer, git catalog, bounded LLM-proposer, CLI).
"""

from synthcyber.adversarial import AdversarialCase, adversarial_corpus
from synthcyber.grounding import (
    field_profile,
    ground,
    grounded_scenario_corpus,
    load_events,
    plausible_fill,
)
from synthcyber.recipe import compose, recipe_cid
from synthcyber.scenarios import Scenario, scenario_positives, t1003_001_scenarios

__all__ = [
    "Scenario",
    "t1003_001_scenarios",
    "scenario_positives",
    "AdversarialCase",
    "adversarial_corpus",
    "recipe_cid",
    "compose",
    # real-data grounding — derive plausible scenarios from real open-source logs (no ML; ML is layer-2)
    "load_events",
    "field_profile",
    "plausible_fill",
    "ground",
    "grounded_scenario_corpus",
]
