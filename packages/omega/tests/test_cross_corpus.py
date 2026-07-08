"""Cross-corpus report — group by provenance, measure the ATT&CK bridge. Pins that the report consumes
source.ruleset, finds shared tokens across corpora, and surfaces concrete cross-corpus joins."""

from pathlib import Path

import pytest

from omega.cli import main
from omega.ir import Atom, Block, CompiledRule, Source
from omega.report import cross_corpus, render_cross

CAR = Path("/Users/shunhonda/dev/csat/data/mitre/car")
SIGMA = Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"


def _rule(rid, ruleset, tags):
    return CompiledRule(id=rid, title=rid, logsource=(), tags=tuple(tags),
                        blocks=(Block("b", 1, (Atom(f"{ruleset}_field", (), ()),)),),
                        condition="", source=Source(ruleset, native_id=rid))


def test_cross_corpus_bridge_and_join():
    rules = [
        _rule("s1", "sigma", ["attack.t1059", "attack.t1003"]),
        _rule("s2", "sigma", ["attack.t1059"]),
        _rule("c1", "car", ["attack.t1059"]),            # bridges s1/s2 on T1059
        _rule("c2", "car", ["attack.t9999"]),            # car-only technique
    ]
    rep = cross_corpus(rules, axis="attack")
    assert rep["corpora"] == ["car", "sigma"]
    assert rep["per_corpus"]["sigma"]["rules"] == 2
    assert rep["pairwise_shared"]["car~sigma"] == 1      # tag:attack.t1059 shared
    assert rep["per_corpus"]["car"]["unique_to_it"] == 1  # t9999
    # concrete join: the shared token lists rules from BOTH corpora
    join = next(j for j in rep["sample_joins"] if "t1059" in j["token"])
    assert join["rules_by_corpus"]["sigma"] and join["rules_by_corpus"]["car"]
    assert "cross-corpus" in render_cross(rep)


def test_field_axis_does_not_bridge():
    rules = [_rule("s1", "sigma", ["attack.t1"]), _rule("c1", "car", ["attack.t1"])]
    rep = cross_corpus(rules, axis="field")
    assert rep["pairwise_shared"]["car~sigma"] == 0     # sigma_field vs car_field -> disjoint vocab


@pytest.mark.skipif(not (CAR.is_dir() and SIGMA.is_dir()), reason="corpora not present")
def test_bridge_cli(capsys):
    rc = main(["bridge", "--sigma", str(SIGMA), "--car", str(CAR)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "cross-corpus bridge" in out
    assert "sigma" in out and "car" in out
