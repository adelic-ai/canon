"""Stage 6 — the CLI. Pins that `run` wires the pipeline end to end, writes artifacts with --out, chooses the
projection from the command line, and fails cleanly on a bad corpus path."""

import json
import os
from pathlib import Path

import pytest

from omega.cli import main

SIGMA = Path(os.environ["OMEGA_SIGMA_CORPUS"]) if os.environ.get("OMEGA_SIGMA_CORPUS") else \
    Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"

_CORPUS = "\n---\n".join(
    f"title: R{i}\nid: 00000000-0000-0000-0000-00000000000{i}\n"
    f"logsource: {{product: windows, category: process_creation}}\n"
    f"detection: {{selection: {{Image|endswith: '\\x{i}.exe'}}, condition: selection}}"
    for i in range(3)
)


def _corpus(tmp_path):
    (tmp_path / "r.yml").write_text(_CORPUS)
    return tmp_path


def test_run_prints_report(tmp_path, capsys):
    rc = main(["run", "--corpus", str(_corpus(tmp_path))])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ingest: 1 files, 3 rules, clean=True" in out
    assert "over-collapse" in out


def test_run_writes_artifacts(tmp_path, capsys):
    out_dir = tmp_path / "out"
    rc = main(["run", "--corpus", str(_corpus(tmp_path)), "--out", str(out_dir)])
    assert rc == 0
    fig = json.loads((out_dir / "figures.json").read_text())
    assert fig["n_rules"] == 3
    assert (out_dir / "lattice.ttl").read_text().startswith("@prefix skos:")


def test_projection_chosen_on_cli(tmp_path, capsys):
    # adding logsource to the aware projection is just a CLI flag — nothing privileged
    main(["run", "--corpus", str(_corpus(tmp_path)), "--aware", "clause,polarity,logsource"])
    assert "'clause', 'logsource', 'polarity'" in capsys.readouterr().out


def test_bad_corpus_path_fails_cleanly(tmp_path, capsys):
    rc = main(["run", "--corpus", str(tmp_path / "nope")])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored corpus not present")
def test_run_over_real_corpus(tmp_path, capsys):
    rc = main(["run", "--corpus", str(SIGMA), "--out", str(tmp_path / "out")])
    assert rc == 0
    assert "3748 rules" in capsys.readouterr().out
