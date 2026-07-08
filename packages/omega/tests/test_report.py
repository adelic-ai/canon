"""Stage 5 — report + figures. Pins the over-collapse numbers, the per-dimension breakdown, artifact emission,
and the corpus-wide reproducible result."""

import json
from pathlib import Path

import pytest

from omega.ingest.sigma import load, load_ir, to_ir
from omega.report import analyze, by_dimension, emit, over_collapse, render

SIGMA = Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"


def _rule(t, product, sel):
    return f"title: {t}\nid: 00000000-0000-0000-0000-0000000000{t}\nlogsource: {{product: {product}, category: process_creation}}\ndetection: {{selection: {sel}, condition: selection}}"


_CORPUS = "\n---\n".join([
    _rule("a1", "windows", "{Image|endswith: '\\a.exe'}"),
    _rule("a2", "windows", "{Image|endswith: '\\b.exe'}"),   # same field as a1, different value
    _rule("a3", "windows", "{Image|endswith: '\\c.exe', CommandLine|contains: 'x'}"),
    _rule("a4", "linux", "{Image|endswith: '/foo'}"),
    _rule("a5", "linux", "{Image|endswith: '/bar'}"),
])


def _irs(tmp_path):
    (tmp_path / "r.yml").write_text(_CORPUS)
    return [to_ir(r) for r in load(tmp_path)[0]]


def test_over_collapse_counts(tmp_path):
    oc = over_collapse(_irs(tmp_path))
    assert oc["n_rules"] == 5
    assert oc["blind_concepts"] < oc["aware_concepts"]     # value-blind collapses same-field rules
    assert oc["aware_concepts"] == 5                       # all distinct values
    assert oc["biggest_blind_class"] >= 2                  # a1,a2 share {Image}


def test_by_dimension_groups_and_thresholds(tmp_path):
    rows = by_dimension(_irs(tmp_path), "product", min_rules=1)
    vals = {r["value"] for r in rows}
    assert vals == {"windows", "linux"}
    assert next(r for r in rows if r["value"] == "windows")["n_rules"] == 3
    # min_rules filters small slices
    assert by_dimension(_irs(tmp_path), "product", min_rules=4) == [
        r for r in rows if r["n_rules"] >= 4]


def test_emit_writes_artifacts(tmp_path):
    out = tmp_path / "out"
    report = emit(_irs(tmp_path), out)
    fig = json.loads((out / "figures.json").read_text())
    assert fig["corpus"]["n_rules"] == 5
    assert "lattice" in fig                                # edges tally present
    ttl = (out / "lattice.ttl").read_text()
    assert "@prefix skos:" in ttl
    assert isinstance(render(report), str) and "over-collapse" in render(report)


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored corpus not present")
def test_corpus_report_reproducible():
    compiled, _ = load_ir(SIGMA)
    r = analyze(compiled)
    assert r["n_rules"] >= 3700
    assert r["corpus"]["blind_concepts"] < r["corpus"]["aware_concepts"]
    assert r["generalizes"] is True                        # aware > blind in every product slice
    # windows is the densest slice with the most dramatic collapse
    win = next(row for row in r["by_dimension"]["rows"] if row["value"] == "windows")
    assert win["biggest_blind_class"] > 100                # hundreds of rules in one field-set concept
