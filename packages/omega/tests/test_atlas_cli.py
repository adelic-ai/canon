"""The `omega atlas` subcommand — pins that it wires ingest -> classify -> output end to end, prints the
acceptance counts, writes both artifacts with --out, and fails cleanly on a bad path."""

import json
from pathlib import Path

from omega.cli import main

_ATLAS_FIXTURE = """\
id: ATLAS
name: Adversarial Threat Landscape for AI Systems
version: test
matrices:
- id: ATLAS
  name: ATLAS Matrix
  tactics: []
  techniques:
  - id: AML.T0010
    name: Bridged Technique
    object-type: technique
    ATT&CK-reference: {id: T1059, url: https://attack.mitre.org/techniques/T1059/}
  - id: AML.T0051
    name: AI-Native Technique
    object-type: technique
"""

_SIGMA_RULE = """\
title: R
id: 00000000-0000-0000-0000-000000000001
tags: [attack.t1059]
logsource: {product: windows, category: process_creation}
detection: {selection: {Image|endswith: '.exe'}, condition: selection}
"""

_CAR_ANALYTIC = """\
title: Demo Analytic
id: CAR-9999-99-999
platforms: [Windows]
"""


def _setup(tmp_path):
    (tmp_path / "sigma").mkdir()
    (tmp_path / "sigma" / "r.yml").write_text(_SIGMA_RULE)
    (tmp_path / "car").mkdir()
    (tmp_path / "car" / "a.yaml").write_text(_CAR_ANALYTIC)
    (tmp_path / "atlas").mkdir()
    (tmp_path / "atlas" / "ATLAS.yaml").write_text(_ATLAS_FIXTURE)
    return tmp_path


def test_atlas_cli_prints_acceptance_counts(tmp_path, capsys):
    _setup(tmp_path)
    rc = main(["atlas", "--sigma", str(tmp_path / "sigma"), "--car", str(tmp_path / "car"),
              "--atlas", str(tmp_path / "atlas" / "ATLAS.yaml")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "atlas coverage — 2 techniques:" in out
    assert "covered(bridged)=1" in out and "silent(no-bridge)=1" in out
    assert "silent(uncovered)=0" in out and "uncertain(CAR-coarse)=0" in out


def test_atlas_cli_writes_artifacts(tmp_path, capsys):
    _setup(tmp_path)
    out_dir = tmp_path / "out"
    rc = main(["atlas", "--sigma", str(tmp_path / "sigma"), "--car", str(tmp_path / "car"),
              "--atlas", str(tmp_path / "atlas"), "--out", str(out_dir)])
    assert rc == 0
    payload = json.loads((out_dir / "atlas_coverage.json").read_text())
    assert payload["n_techniques"] == 2
    assert payload["counts"]["covered(bridged)"] == 1
    row = next(r for r in payload["table"] if r["technique"] == "AML.T0010")
    assert row["status"] == "covered(bridged)" and row["rules"] == ["00000000-0000-0000-0000-000000000001"]
    ttl = (out_dir / "atlas_coverage.ttl").read_text()
    assert "@prefix skos:" in ttl and "AML.T0010" in ttl


def test_atlas_cli_bad_atlas_path_fails_cleanly(tmp_path, capsys):
    _setup(tmp_path)
    rc = main(["atlas", "--sigma", str(tmp_path / "sigma"), "--car", str(tmp_path / "car"),
              "--atlas", str(tmp_path / "nope")])
    assert rc == 2
    assert "error:" in capsys.readouterr().err
