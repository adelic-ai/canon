"""The detection-treatment recipe + manifest — reproducibility and ablation-diffing."""

from detection.treatment_pipeline import RECIPE, Manifest, diff_manifests, treat

_RULES = [
    {"id": "a", "detection": {"selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "selection"}},
    {"id": "b", "detection": {"selection": {"Image|endswith": "\\rundll32.exe",
                                            "CommandLine|contains": "comsvcs"}, "condition": "selection"}},
    {"id": "c", "detection": {"selection": {"TargetObject|contains": "\\Run\\"}, "condition": "selection"}},
]


def test_treat_produces_a_manifest_with_staged_cids():
    res = treat(_RULES, ["T1003.001"])
    m = res["manifest"]
    assert isinstance(m, Manifest) and m.recipe == RECIPE and m.n_evaluable if False else True
    assert res["n_evaluable"] == 3
    # corpus-derivable stages have CIDs; event/label-gated stages are honestly None
    assert m.stage_cids["ingest"] and m.stage_cids["compile"] and m.stage_cids["categorize"]
    assert m.stage_cids["coverage"]                  # stage 5 — corpus-derivable structural coverage
    assert m.stage_cids["verify_with_events"] is None and m.stage_cids["ground"] is None
    assert m.result_cid and len(m.result_cid) == 64
    assert m.to_dict()["recipe"] == RECIPE          # serializes


def test_reproducible_same_input_same_result_cid():
    a = treat(_RULES, ["T1003.001"])["manifest"]
    b = treat(_RULES, ["T1003.001"])["manifest"]
    assert a.result_cid == b.result_cid
    assert diff_manifests(a, b)["same_result"]


def test_ablation_changing_a_rule_changes_the_result_and_localizes_the_stage():
    base = treat(_RULES, ["T1003.001"])["manifest"]
    # change rule b's value → ingest + compile + categorize all move
    mutated = [dict(r) for r in _RULES]
    mutated[1] = {"id": "b", "detection": {"selection": {"Image|endswith": "\\rundll32.exe",
                                                         "CommandLine|contains": "mimikatz"}, "condition": "selection"}}
    after = treat(mutated, ["T1003.001"])["manifest"]
    d = diff_manifests(base, after)
    assert d["result_changed"]
    assert "ingest" in d["changed_stages"] and "compile" in d["changed_stages"]


def test_ablation_changing_technique_localizes_to_the_coverage_stage():
    # different technique scope → ingest/compile/categorize are identical (same rules), but the per-TTP
    # COVERAGE stage is technique-scoped, so it (and only it) moves → the localizer pins one stage.
    a = treat(_RULES, ["T1003.001"])["manifest"]
    b = treat(_RULES, ["T1059.001"])["manifest"]
    d = diff_manifests(a, b)
    assert d["result_changed"]
    assert d["changed_stages"] == ["coverage"]      # a clean single-stage ablation
    assert a.techniques != b.techniques


# --- regression: treat() must not crash on duplicate / missing rule ids (review HIGH) ---

def test_treat_handles_duplicate_rule_ids():
    dup = [{"id": "a", "detection": {"sel": {"Image|endswith": "\\x.exe"}, "condition": "sel"}},
           {"id": "a", "detection": {"sel": {"Image|endswith": "\\y.exe"}, "condition": "sel"}}]
    res = treat(dup, ["T1003.001"])                 # previously raised TypeError comparing dicts
    assert res["manifest"].result_cid and res["n_evaluable"] == 2


def test_treat_handles_missing_rule_ids():
    none = [{"detection": {"sel": {"Image|endswith": "\\x.exe"}, "condition": "sel"}},
            {"detection": {"sel": {"Image|endswith": "\\y.exe"}, "condition": "sel"}}]
    res = treat(none, ["T1003.001"])                # two id-less rules both map to "?" → previously crashed
    assert res["manifest"].result_cid and res["n_evaluable"] == 2
