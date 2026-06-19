"""Detection admission — evaluate a candidate detection's code logic against its neighbors.

Structural relation (corpus-free, pure), behavioral differential coverage + fidelity (eval_python, no rdflib),
the admit decision (synonym → reject; novel + warranted → admit; no coverage → abstain), and the optional
D3FEND situate (gated on the vendored ttl).
"""

import importlib.util
from pathlib import Path

import pytest

from detection.admission import (
    Neighbor,
    evaluate_against_neighbors,
    situate_d3fend,
    structural_relation,
)
from detection.motif import from_sigma


def _rule(sel: dict) -> dict:
    return {"id": "r", "detection": {"selection": sel, "condition": "selection"}}


COMSVCS = from_sigma(_rule({"CallTrace|contains": "comsvcs.dll"}))
COMSVCS2 = from_sigma(_rule({"CallTrace|contains": "comsvcs.dll"}))                       # same clauses
STRICTER = from_sigma(_rule({"CallTrace|contains": "comsvcs.dll", "TargetImage|endswith": "\\lsass.exe"}))
OTHER = from_sigma(_rule({"SourceImage|endswith": "\\rundll32.exe"}))                     # no shared clause


def test_structural_relation_classifies_the_logic():
    assert structural_relation(COMSVCS, COMSVCS2) == "synonym"          # identical clause sets
    assert structural_relation(STRICTER, COMSVCS) == "subsumed_by"      # candidate stricter (extra clause)
    assert structural_relation(COMSVCS, STRICTER) == "subsumes"         # candidate more general
    assert structural_relation(COMSVCS, OTHER) == "disjoint"            # no shared clause


def test_synonym_is_rejected_as_redundant():
    rep = evaluate_against_neighbors(
        COMSVCS, [Neighbor("nbr", COMSVCS2)],
        positives=[{"CallTrace": "x comsvcs.dll y"}], technique="T1003.001")
    assert rep["is_synonym"] and rep["admit"] is False
    assert "redundant" in rep["reason"]


def test_novel_coverage_is_admitted_and_localized():
    # candidate is more general than the neighbor → it catches a positive the (stricter) neighbor misses
    positives = [
        {"CallTrace": "x comsvcs.dll y", "GrantedAccess": "0x1010"},     # neighbor's extra clause fails here
        {"CallTrace": "x comsvcs.dll y", "GrantedAccess": "0x1fffff"},
    ]
    neighbor = Neighbor("strict", from_sigma(_rule(
        {"CallTrace|contains": "comsvcs.dll", "GrantedAccess|eq": "0x1fffff"})))
    rep = evaluate_against_neighbors(COMSVCS, [neighbor], positives, technique="T1003.001")
    assert rep["admit"] is True
    assert rep["differential"]["novel"]                                 # catches what the neighbor cannot
    assert rep["fidelity"]["coverage"] == "true" and rep["fidelity"]["fired"] == 2
    assert len(rep["warrant_cid"]) == 64


def test_neighbor_only_coverage_is_recorded():
    # candidate misses an instance the neighbor catches → recorded as neighbor_only (the candidate's gap)
    positives = [{"SourceImage": "C:\\X\\rundll32.exe"}]                # only OTHER's clause matches
    rep = evaluate_against_neighbors(COMSVCS, [Neighbor("o", OTHER)], positives, technique="T1003.001")
    assert rep["differential"]["neighbor_only"]
    assert rep["fidelity"]["coverage"] == "false"


def test_no_ground_truth_abstains_not_admits():
    rep = evaluate_against_neighbors(COMSVCS, [Neighbor("o", OTHER)], positives=[], technique="T1003.001")
    assert rep["fidelity"]["coverage"] == "none" and rep["admit"] is False   # can't earn warrant → abstain


_D3FEND = Path(__file__).parents[2] / "semantic-cyber/data/d3fend.ttl"   # .../packages/semantic-cyber/...
_have_d3fend = _D3FEND.exists() and importlib.util.find_spec("semantic_cyber") is not None


@pytest.mark.skipif(not _have_d3fend, reason="D3FEND ttl / semantic_cyber not present")
def test_situate_d3fend_returns_defensive_context():
    s = situate_d3fend("T1003.001")
    assert s is not None and "defensive_techniques" in s
    assert isinstance(s["defensive_techniques"], list)
