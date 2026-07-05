"""Stage 1 — map pySigma's AST to omega's agnostic IR. Pins atom extraction and, the load-bearing part,
that filter blocks are read as -1 polarity from the condition; and that the mapper is total over the corpus."""

from pathlib import Path

import pytest

from omega.ingest.sigma import load, load_ir, to_ir

SIGMA = Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"

_FILTER_RULE = """\
title: Demo Filter
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '.exe'
    CommandLine|contains: 'foo'
  filter_main:
    ParentImage|contains: 'Program Files'
  condition: selection and not 1 of filter_*
"""


def test_to_ir_atoms_and_filter_polarity(tmp_path):
    (tmp_path / "r.yml").write_text(_FILTER_RULE)
    rules, _ = load(tmp_path)
    ir = to_ir(rules[0])

    blocks = {b.name: b for b in ir.blocks}
    assert blocks["selection"].polarity == 1
    assert blocks["filter_main"].polarity == -1          # read from 'not 1 of filter_*'

    atoms = {a.field: a for a in blocks["selection"].atoms}
    assert atoms["Image"].mods == ("endswith",)
    assert "exe" in atoms["Image"].values[0]             # value carries pySigma's endswith transform
    assert atoms["CommandLine"].mods == ("contains",)
    assert ir.logsource == (("category", "process_creation"), ("product", "windows"))   # open (dim, value) pairs
    assert "not 1 of filter_*" in ir.condition           # raw condition retained as polarity provenance


def test_bare_not_filter_polarity(tmp_path):
    (tmp_path / "r.yml").write_text(_FILTER_RULE.replace("not 1 of filter_*", "not filter_main"))
    rules, _ = load(tmp_path)
    ir = to_ir(rules[0])
    assert {b.name: b.polarity for b in ir.blocks} == {"selection": 1, "filter_main": -1}


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored corpus not present")
def test_load_ir_is_total_and_finds_filters():
    compiled, report = load_ir(SIGMA)
    assert len(compiled) == report.rules                 # to_ir is total — every base rule maps to the IR
    filters = sum(1 for r in compiled for b in r.blocks if b.polarity == -1)
    assert filters > 0                                   # the corpus's filter blocks are detected as -1
