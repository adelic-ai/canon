"""ATLAS spine ingest. Pins that the adapter lowers to AtlasTechnique (not CompiledRule — it's a spine,
not a rule corpus), reads ATT&CK-reference into the bridge-ready tag format, records subtechnique
parentage without inheriting the parent's tactics, and is total + error-isolating like the rule adapters."""

import os
from pathlib import Path

import pytest

from omega.ingest import atlas
from omega.ir import AtlasTechnique, Source

ATLAS_DATA = Path(os.environ["OMEGA_ATLAS_CORPUS"]) if os.environ.get("OMEGA_ATLAS_CORPUS") else None

_FIXTURE = """\
id: ATLAS
name: Adversarial Threat Landscape for AI Systems
version: test
matrices:
- id: ATLAS
  name: ATLAS Matrix
  tactics:
  - id: AML.TA0002
    name: Reconnaissance
  techniques:
  - id: AML.T0000
    name: Search Open Technical Databases
    object-type: technique
    ATT&CK-reference: {id: T1596, url: https://attack.mitre.org/techniques/T1596/}
    tactics: [AML.TA0002]
  - id: AML.T0000.000
    name: Journals and Conference Proceedings
    object-type: technique
    specializes: AML.T0000
  - id: AML.T0043
    name: Craft Adversarial Data
    object-type: technique
    tactics: [AML.TA0001]
  - id: AML.T0091.000
    name: A subtechnique with its own ATT&CK reference
    object-type: technique
    specializes: AML.T0091
    ATT&CK-reference: {id: T1550.001, url: https://attack.mitre.org/techniques/T1550/001/}
  mitigations:
  - id: AML.M0000
    name: Limit Public Release of Information
case-studies:
- id: AML.CS0000
  name: Some Case Study
"""


def _write(tmp_path, text=_FIXTURE):
    p = tmp_path / "ATLAS.yaml"
    p.write_text(text)
    return p


def test_load_ir_totals_and_isolates(tmp_path):
    path = _write(tmp_path)
    techs, report = atlas.load_ir(path)
    assert report.files == 1 and report.rules == 4 and report.clean
    assert len(techs) == 4
    assert all(isinstance(t, AtlasTechnique) for t in techs)


def test_locates_dist_atlas_yaml_under_a_checkout_root(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "ATLAS.yaml").write_text(_FIXTURE)
    techs, report = atlas.load_ir(tmp_path)          # pointed at the checkout root, not the file
    assert report.rules == 4 and len(techs) == 4


def test_base_technique_has_attack_ref_and_no_parent(tmp_path):
    techs, _ = atlas.load_ir(_write(tmp_path))
    by_id = {t.id: t for t in techs}
    t0000 = by_id["AML.T0000"]
    assert t0000.attack_refs == ("attack.t1596",)             # Sigma tag format, bridge-ready
    assert t0000.parent is None
    assert t0000.tactics == ("AML.TA0002",)
    assert t0000.source == Source("atlas", native_id="AML.T0000", path=str(_write(tmp_path)))


def test_subtechnique_carries_parent_and_does_not_inherit_tactics(tmp_path):
    techs, _ = atlas.load_ir(_write(tmp_path))
    by_id = {t.id: t for t in techs}
    sub = by_id["AML.T0000.000"]
    assert sub.parent == "AML.T0000"
    assert sub.tactics == ()                                  # NOT inherited from AML.T0000 (DECISIONS.md)
    assert sub.attack_refs == ()                               # this subtechnique has no ATT&CK reference


def test_ai_native_technique_has_no_attack_ref(tmp_path):
    """AML.T0043 (Craft Adversarial Data) has no ATT&CK-reference in the fixture — the structural-silence
    case the coverage classifier must distinguish from a fillable gap."""
    techs, _ = atlas.load_ir(_write(tmp_path))
    by_id = {t.id: t for t in techs}
    assert by_id["AML.T0043"].attack_refs == ()


def test_subtechnique_can_carry_its_own_attack_ref(tmp_path):
    techs, _ = atlas.load_ir(_write(tmp_path))
    by_id = {t.id: t for t in techs}
    assert by_id["AML.T0091.000"].attack_refs == ("attack.t1550.001",)


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        atlas.load_ir(tmp_path / "nope")


@pytest.mark.skipif(not (ATLAS_DATA and ATLAS_DATA.exists()), reason="ATLAS corpus not present")
def test_loads_real_corpus_and_is_mostly_bridge_silent():
    techs, report = atlas.load_ir(ATLAS_DATA)
    assert report.clean and len(techs) > 100
    with_bridge = sum(1 for t in techs if t.attack_refs)
    # sanity check per ATLAS-SPEC.md §6 / §4: most ATLAS techniques have no ATT&CK analog at all
    assert with_bridge < len(techs) / 2
