"""Stage 4 — SKOS graded relations. Pins the relation grades (exact/narrow/broad/related), tightness,
why(), Turtle emit, and that relate() runs over the whole corpus and produces a graded lattice."""

from pathlib import Path

import pytest

from omega.axes import CONTENT
from omega.ingest.sigma import load, load_ir, to_ir
from omega.skos import counts, relate, relation, tightness, to_turtle, why

SIGMA = Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"

_LS = "logsource: {product: windows, category: process_creation}"
_RULES = f"""\
title: A
id: 00000000-0000-0000-0000-00000000000a
{_LS}
detection: {{selection: {{Image|endswith: '\\a.exe'}}, condition: selection}}
---
title: B
id: 00000000-0000-0000-0000-00000000000b
{_LS}
detection: {{selection: {{Image|endswith: '\\a.exe'}}, condition: selection}}
---
title: C
id: 00000000-0000-0000-0000-00000000000c
{_LS}
detection: {{selection: {{Image|endswith: '\\a.exe', CommandLine|contains: 'x'}}, condition: selection}}
---
title: D
id: 00000000-0000-0000-0000-00000000000d
{_LS}
detection: {{selection: {{Image|endswith: '\\a.exe', CommandLine|contains: 'y'}}, condition: selection}}
"""


def _irs(tmp_path):
    (tmp_path / "r.yml").write_text(_RULES)
    return {r.title: ir for r, ir in ((r, to_ir(r)) for r in load(tmp_path)[0])}


def test_relation_grades():
    assert relation(frozenset({"x"}), frozenset({"x"})) == "exact"
    assert relation(frozenset({"x", "y"}), frozenset({"x"})) == "narrower"   # more tokens -> stricter
    assert relation(frozenset({"x"}), frozenset({"x", "y"})) == "broader"
    assert relation(frozenset({"x", "y"}), frozenset({"x", "z"})) == "related"
    assert relation(frozenset({"x"}), frozenset({"z"})) is None              # disjoint -> no edge
    assert relation(frozenset(), frozenset({"x"})) is None


def test_tightness_and_why():
    a, b = frozenset({"x", "y"}), frozenset({"x", "z"})
    assert tightness(a, b) == 1 / 3                     # shared 1, union 3 (cardinality Jaccard)
    assert tightness(a, a) == 1.0
    w = why(a, b)
    assert w["shared"] == ["x"] and w["a_only"] == ["y"] and w["b_only"] == ["z"]


def test_relate_grades_over_rules(tmp_path):
    irs = _irs(tmp_path)
    edges = relate(list(irs.values()), axes={"clause"}, idf_weighted=False)
    pairs = {(min(e.a, e.b), max(e.a, e.b)): e.rel for e in edges}
    aid, bid, cid, did = (irs[t].id for t in "ABCD")

    assert pairs[(min(aid, bid), max(aid, bid))] == "exact"        # A,B identical
    # C is narrower than A (adds CommandLine); direction is relative, so check the rel resolves to a subsumption
    ac = next(e for e in edges if {e.a, e.b} == {aid, cid})
    assert ac.rel in ("narrower", "broader")                       # subsumption, not related
    cd = next(e for e in edges if {e.a, e.b} == {cid, did})
    assert cd.rel == "related"                                     # share Image, differ on CommandLine


def test_turtle_emit(tmp_path):
    irs = _irs(tmp_path)
    ttl = to_turtle(relate(list(irs.values()), axes={"clause"}))
    assert "@prefix skos:" in ttl and "skos:exactMatch" in ttl
    assert ":" + irs["A"].id in ttl


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored corpus not present")
def test_relate_over_corpus():
    compiled, _ = load_ir(SIGMA)
    edges = relate(compiled, axes=CONTENT)
    c = counts(edges)
    assert edges and set(c) <= {"exact", "close", "narrower", "broader", "related"}
    assert c.get("exact", 0) >= 11         # the 11 identical-logic pairs surface as exactMatch synonyms
    ttl = to_turtle(edges)
    assert ttl.count("skos:") >= len(edges)
