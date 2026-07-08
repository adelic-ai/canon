"""Adapter #2 — CAR ingest (structured axes) + the cross-corpus ATT&CK bridge. Pins that CAR maps to the
same agnostic IR, carries provenance, honestly defers its unparsed query logic, and that ATT&CK bridges CAR
to Sigma while their field vocabularies do not (the predicted result)."""

from pathlib import Path

import pytest

from omega.axes import attributes
from omega.ingest import car
from omega.ingest.sigma import load_ir as sigma_load_ir
from omega.ir import CompiledRule, Source

CAR = Path("/Users/shunhonda/dev/csat/data/mitre/car")
SIGMA = Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"

_ANALYTIC = """\
title: Demo Analytic
id: CAR-9999-99-999
platforms: [Windows, Linux]
coverage:
  - technique: T1543
    subtechniques: [T1543.003]
  - technique: T1053
data_model_references:
  - process/create/exe
  - process/create/parent_exe
implementations:
  - type: Splunk
    code: 'index=x Image=*'
"""


def test_car_to_ir_maps_structured_axes(tmp_path):
    (tmp_path / "a.yaml").write_text(_ANALYTIC)
    rules, report = car.load_ir(tmp_path)
    assert report.files == 1 and report.rules == 1
    assert report.deferred.get("unparsed-implementations") == 1     # honest: SPL logic not parsed
    r = rules[0]
    assert isinstance(r, CompiledRule)
    assert r.id == "CAR-9999-99-999"
    assert r.source == Source("car", native_id="CAR-9999-99-999", path=str(tmp_path / "a.yaml"))
    # coverage -> ATT&CK tags (technique + subtechnique), Sigma format
    assert set(r.tags) == {"attack.t1543", "attack.t1543.003", "attack.t1053"}
    # platforms -> product logsource
    assert r.logsource == (("product", "linux"), ("product", "windows"))
    # data_model_references -> coarse CAR-vocab field atoms
    fields = {a.field for b in r.blocks for a in b.atoms}
    assert fields == {"exe", "parent_exe"}


@pytest.mark.skipif(not CAR.is_dir(), reason="CAR corpus not present")
def test_car_loads_corpus_clean():
    rules, report = car.load_ir(CAR)
    assert report.rules >= 100 and report.clean
    assert all(r.source and r.source.ruleset == "car" for r in rules)


@pytest.mark.skipif(not (CAR.is_dir() and SIGMA.is_dir()), reason="corpora not present")
def test_attack_bridges_car_to_sigma():
    sigma_rules, _ = sigma_load_ir(SIGMA)
    car_rules, _ = car.load_ir(CAR)
    # collect the ATT&CK tokens each corpus emits
    sigma_attack = {t for r in sigma_rules for t in attributes(r, axes={"attack"})}
    car_attack = {t for r in car_rules for t in attributes(r, axes={"attack"})}
    shared = sigma_attack & car_attack
    assert len(shared) > 20                     # ATT&CK is the free cross-corpus bridge

    # field vocab does NOT bridge: CAR's coarse fields are its own vocabulary, mostly disjoint from Sigma's
    sigma_fields = {t for r in sigma_rules for t in attributes(r, axes={"field"})}
    car_fields = {t for r in car_rules for t in attributes(r, axes={"field"})}
    assert car_fields and (len(car_fields & sigma_fields) / len(car_fields)) < 0.5
