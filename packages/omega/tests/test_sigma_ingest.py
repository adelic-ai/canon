"""Stage 0 — the Sigma adapter's ingest. Pins that pySigma reads the whole vendored corpus with zero errors,
and that the loader is total (records failures rather than raising) and deterministic."""

import os
from pathlib import Path

import pytest

from omega.ingest.sigma import ParseReport, load

# the vendored SigmaHQ corpus lives in a sibling package (data, not code)
SIGMA = Path(os.environ["OMEGA_SIGMA_CORPUS"]) if os.environ.get("OMEGA_SIGMA_CORPUS") else \
    Path(__file__).resolve().parents[2] / "semantic-cyber/data/sigma-rules"


@pytest.mark.skipif(not SIGMA.is_dir(), reason="vendored sigma-rules corpus not present")
def test_parses_whole_corpus_clean():
    rules, report = load(SIGMA)
    assert report.files >= 3700                      # ~3,748 rule files
    assert report.rules >= 3700
    assert report.clean                              # the verified result: pySigma parses every one, 0 errors
    assert len(rules) == report.rules
    r = rules[0]                                      # returned items are parsed pySigma rules
    assert hasattr(r, "detection") and hasattr(r, "logsource")


def test_is_total_on_a_broken_file(tmp_path):
    """A malformed file is recorded or skipped, never raised — the loader is total."""
    (tmp_path / "broken.yml").write_text("title: x\n  bad: [unterminated\n")
    rules, report = load(tmp_path)
    assert report.files == 1
    assert report.rules == 0                          # nothing valid parsed, and no exception escaped
    assert isinstance(report, ParseReport)


def test_deterministic_order(tmp_path):
    (tmp_path / "b.yml").write_text(_RULE.format(t="B"))
    (tmp_path / "a.yml").write_text(_RULE.format(t="A"))
    rules, report = load(tmp_path)
    assert report.rules == 2
    assert [r.title for r in rules] == ["A", "B"]     # sorted by path -> a.yml before b.yml


def test_missing_or_nondir_root_raises(tmp_path):
    """A wrong path must not masquerade as a clean-but-empty load (files=0, clean=True)."""
    with pytest.raises(FileNotFoundError):
        load(tmp_path / "does-not-exist")
    afile = tmp_path / "afile.yml"
    afile.write_text("title: x\n")
    with pytest.raises(NotADirectoryError):
        load(afile)                                   # a file, not a directory


_RULE = """\
title: {t}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\{t}.exe'
  condition: selection
"""
