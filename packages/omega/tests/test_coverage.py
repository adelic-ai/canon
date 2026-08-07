"""ATLAS coverage cartography — the transitive bridge + five-way classifier. Pins the honest-silence
attribution that is the point of ATLAS-SPEC.md §4: direct beats bridged beats CAR-only, an AI-native
technique (no ATT&CK reference at all) reads structurally silent, and a technique WITH a reference but no
covering rule reads as a fillable gap — a different claim, not conflated with either."""

from omega.coverage import Coverage, attack_bridge_index, classify, render, summary, table, to_turtle
from omega.ir import AtlasTechnique, CompiledRule, Source


def _tech(tid, *, attack_refs=(), name=None):
    return AtlasTechnique(id=tid, name=name or tid, tactics=(), parent=None, attack_refs=attack_refs)


def _rule(rid, ruleset, tags=(), *, atlas_tag=None):
    all_tags = tuple(tags) + ((atlas_tag,) if atlas_tag else ())
    return CompiledRule(id=rid, title=rid, logsource=(), tags=all_tags, blocks=(), condition="",
                        source=Source(ruleset, native_id=rid))


def test_attack_bridge_index_maps_tag_to_techniques():
    techs = [_tech("AML.T0010", attack_refs=("attack.t1059",)),
             _tech("AML.T0020", attack_refs=("attack.t1059", "attack.t1003"))]
    idx = attack_bridge_index(techs)
    assert idx["tag:attack.t1059"] == ["AML.T0010", "AML.T0020"]
    assert idx["tag:attack.t1003"] == ["AML.T0020"]


def test_direct_beats_everything():
    t = _tech("AML.T0043", attack_refs=("attack.t1059",))
    direct = _rule("s1", "sigma", atlas_tag="atlas.aml.t0043")
    bridged = _rule("s2", "sigma", tags=("attack.t1059",))
    cov = classify([t], [direct, bridged])
    assert cov == [Coverage("AML.T0043", "covered(direct)", ("s1",), ())]


def test_bridged_via_sigma_attack_tag():
    t = _tech("AML.T0010", attack_refs=("attack.t1059",))
    r = _rule("s1", "sigma", tags=("attack.t1059",))
    cov = classify([t], [r])
    assert cov == [Coverage("AML.T0010", "covered(bridged)", ("s1",), ("tag:attack.t1059",))]


def test_sigma_beats_car_when_both_bridge():
    t = _tech("AML.T0010", attack_refs=("attack.t1059",))
    s = _rule("s1", "sigma", tags=("attack.t1059",))
    c = _rule("c1", "car", tags=("attack.t1059",))
    cov = classify([t], [s, c])
    assert cov[0].status == "covered(bridged)" and cov[0].rules == ("s1",)


def test_car_only_bridge_is_uncertain_not_covered_or_silent():
    """ATLAS-SPEC.md §5: a CAR-only path to coverage is a blind spot in omega's parsing, not a real gap."""
    t = _tech("AML.T0010", attack_refs=("attack.t1059",))
    c = _rule("c1", "car", tags=("attack.t1059",))
    cov = classify([t], [c])
    assert cov == [Coverage("AML.T0010", "uncertain(CAR-coarse)", ("c1",), ("tag:attack.t1059",))]


def test_no_attack_reference_is_structurally_silent():
    """AI-native technique — no rule library speaking only ATT&CK could ever reach it."""
    t = _tech("AML.T0051", attack_refs=())
    cov = classify([t], [_rule("s1", "sigma", tags=("attack.t9999",))])
    assert cov == [Coverage("AML.T0051", "silent(no-bridge)", (), ())]


def test_has_reference_but_no_covering_rule_is_a_fillable_gap():
    t = _tech("AML.T0010", attack_refs=("attack.t1059",))
    cov = classify([t], [_rule("s1", "sigma", tags=("attack.t9999",))])   # unrelated tag
    assert cov == [Coverage("AML.T0010", "silent(uncovered)", (), ())]


def test_summary_counts_all_five_statuses_and_sums_to_total():
    techs = [_tech("A", attack_refs=("attack.t1",)), _tech("B", attack_refs=("attack.t2",)),
             _tech("C", attack_refs=("attack.t3",)), _tech("D", attack_refs=()), _tech("E", attack_refs=())]
    rules = [_rule("s1", "sigma", atlas_tag="atlas.a"),
             _rule("s2", "sigma", tags=("attack.t2",)),
             _rule("c1", "car", tags=("attack.t3",))]
    cov = classify(techs, rules)
    counts = summary(cov)
    assert counts == {
        "covered(direct)": 1, "covered(bridged)": 1, "uncertain(CAR-coarse)": 1,
        "silent(no-bridge)": 2, "silent(uncovered)": 0,
    }
    assert sum(counts.values()) == len(techs)
    assert "atlas coverage — 5 techniques:" in render(counts)
    for status in counts:
        assert status in render(counts)


def test_table_carries_name_and_provenance():
    t = _tech("AML.T0010", attack_refs=("attack.t1059",), name="Some Technique")
    cov = classify([t], [_rule("s1", "sigma", tags=("attack.t1059",))])
    rows = table(cov, [t])
    assert rows == [{"technique": "AML.T0010", "name": "Some Technique", "status": "covered(bridged)",
                     "rules": ["s1"], "via": ["tag:attack.t1059"]}]


def test_turtle_only_emits_edges_for_covered_statuses():
    techs = [_tech("AML.T0010", attack_refs=("attack.t1059",)), _tech("AML.T0020", attack_refs=())]
    rules = [_rule("s1", "sigma", tags=("attack.t1059",))]
    cov = classify(techs, rules)
    ttl = to_turtle(cov)
    assert "@prefix skos:" in ttl
    assert "AML.T0010" in ttl and "skos:relatedMatch" in ttl and "s1" in ttl
    assert "AML.T0020" not in ttl                       # silent(no-bridge) -> no asserted relation
