"""Workspace — the engine/workspace boundary first slice.

The manifest round-trips without any data (pure engine state). The corpus-gated tests prove the load-bearing
claims: the engine runs against a *swappable* workspace (corpus + ruleset come from the workspace, not the
code), writes its findings *into* the workspace, and a re-run with a changed ruleset pin produces a different,
diffable derivation — while the structural verdict stays put.
"""

import shutil
from pathlib import Path

import pytest

from detection.sigma_panel import SIGMA, gather
from detection.workspace import (
    Ruleset,
    Source,
    Workspace,
    diff_derived,
    load_derived,
    run_lsass_location_coverage,
)

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
_have_corpus = OTRF.exists() and SIGMA.exists()


def test_manifest_round_trips_without_data(tmp_path):
    ws = Workspace(
        root=str(tmp_path / "ws"),
        sources=(Source(ref="/data/otrf.json", kind="sysmon", retention_window="90d", cid="cid:abc"),),
        ruleset=Ruleset(corpus_ref="/rules", version="sigma-2026.06"),
        recipes=("cid:recipe1",),
    )
    ws.save()
    back = Workspace.load(ws.root)
    assert back == ws                                              # full round-trip, engine holds no data
    assert back.source_of("sysmon").retention_window == "90d"
    assert back.source_of("kerberos") is None
    assert back.derived_dir.endswith("/derived")


@pytest.mark.skipif(not _have_corpus, reason="OTRF corpus / SigmaHQ rules not present")
def test_engine_reads_from_and_writes_into_the_workspace(tmp_path):
    ws = Workspace(
        root=str(tmp_path / "engagement-A"),
        sources=(Source(ref=str(OTRF), kind="sysmon", retention_window="1y"),),
        ruleset=Ruleset(corpus_ref=str(SIGMA), version="sigma-full"),
    )
    ws.save()
    cov, cid = run_lsass_location_coverage(ws)

    # read FROM the workspace: corpus + ruleset drove the run
    assert cov.verdict.to_contract()["decision"] == "true"
    assert any("comsvcs" in w["rule"] for w in cov.witnesses)
    # write INTO the workspace: the derived artifact is content-addressed in the workspace's store
    art = load_derived(ws, cid)
    assert art["kind"] == "location_coverage" and art["corpus"] == str(OTRF)
    assert art["ruleset"]["version"] == "sigma-full"
    assert (Path(ws.derived_dir) / f"{cid}.json").exists()


@pytest.mark.skipif(not _have_corpus, reason="OTRF corpus / SigmaHQ rules not present")
def test_swappable_ruleset_pin_changes_coverage_not_the_verdict(tmp_path):
    """A second workspace with only the comsvcs rule pinned: the structural verdict is unchanged, but the
    gap set collapses — proving the ruleset is a swappable workspace input and the engine carries no state."""
    # ruleset A: the full SigmaHQ corpus
    ws_full = Workspace(
        root=str(tmp_path / "A"),
        sources=(Source(ref=str(OTRF), kind="sysmon"),),
        ruleset=Ruleset(corpus_ref=str(SIGMA), version="sigma-full"),
    )
    # ruleset B: a one-rule corpus (just comsvcs), in this workspace's own dir
    one_rule_dir = tmp_path / "B" / "rules"
    one_rule_dir.mkdir(parents=True)
    comsvcs = next(p for p, _ in gather("T1003.001", root=SIGMA) if "comsvcs" in p.name)
    shutil.copy(comsvcs, one_rule_dir)
    ws_one = Workspace(
        root=str(tmp_path / "B"),
        sources=(Source(ref=str(OTRF), kind="sysmon"),),
        ruleset=Ruleset(corpus_ref=str(one_rule_dir), version="sigma-comsvcs-only"),
    )

    cov_full, cid_full = run_lsass_location_coverage(ws_full)
    cov_one, cid_one = run_lsass_location_coverage(ws_one)

    # the structural primary is identical across rulesets; coverage is what moves
    assert cov_full.verdict.to_contract()["decision"] == cov_one.verdict.to_contract()["decision"] == "true"
    assert any("comsvcs" in w["rule"] for w in cov_one.witnesses)   # the one rule still fires as a witness
    assert len(cov_one.gaps) < len(cov_full.gaps)                   # the other rules' gaps are gone
    # separate workspaces hold separate stores — no shared/engine state
    assert Path(ws_full.derived_dir, f"{cid_full}.json").exists()
    assert Path(ws_one.derived_dir, f"{cid_one}.json").exists()
    assert ws_full.derived_dir != ws_one.derived_dir


@pytest.mark.skipif(not _have_corpus, reason="OTRF corpus / SigmaHQ rules not present")
def test_rerun_with_changed_pin_diffs_against_prior(tmp_path):
    """Re-analysis concrete: re-derive with a changed ruleset pin, diff against the prior derivation —
    verdict stable, gaps moved, and the diff names which rules left the gap set."""
    one_rule_dir = tmp_path / "rules"
    one_rule_dir.mkdir()
    comsvcs = next(p for p, _ in gather("T1003.001", root=SIGMA) if "comsvcs" in p.name)
    shutil.copy(comsvcs, one_rule_dir)

    ws = Workspace(root=str(tmp_path / "ws"),
                   sources=(Source(ref=str(OTRF), kind="sysmon"),),
                   ruleset=Ruleset(corpus_ref=str(SIGMA), version="sigma-full"))
    _, cid_prior = run_lsass_location_coverage(ws)

    rerun = Workspace(root=ws.root, sources=ws.sources,
                      ruleset=Ruleset(corpus_ref=str(one_rule_dir), version="sigma-comsvcs-only"))
    _, cid_rerun = run_lsass_location_coverage(rerun)

    assert cid_prior != cid_rerun                                  # a different pin → a different derivation
    d = diff_derived(load_derived(ws, cid_prior), load_derived(rerun, cid_rerun))
    assert d["verdict_changed"] is False                           # structural primary unchanged
    assert d["gaps_removed"]                                       # the dropped rules' gaps are named
    assert d["ruleset_prior"]["version"] == "sigma-full"
    assert d["ruleset_rerun"]["version"] == "sigma-comsvcs-only"
