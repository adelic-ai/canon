"""Detection motif IR — the first slice: two molecules, two emitters, agreement attested.

The load-bearing test is :func:`test_emitters_agree_on_otrf_corpus` — the Python and SPARQL emitters must
agree on *every* event in the real corpus, else the IR is lossy. The rest pin parse fidelity, emitter ↔
``sigma_eval`` parity, the RDF view, and the selector-as-provenance hole-closure.
"""

from pathlib import Path

import pytest

from detection.motif import (
    FieldMatch,
    MotifGraph,
    attest_emitter_agreement,
    eval_python,
    eval_sparql,
    from_sigma,
    record_selector_provenance,
    to_rdf,
    to_sparql,
)
from detection.sigma_eval import evaluate_rule
from detection.sigma_panel import SIGMA, gather
from detection.subgraph import load_sysmon_events

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
_have_corpus = OTRF.exists() and SIGMA.exists()


# A self-contained comsvcs-shaped rule, so the parse/emitter tests run without the corpus present.
COMSVCS_RULE = {
    "id": "test-comsvcs",
    "detection": {
        "selection": {
            "TargetImage|endswith": "\\lsass.exe",
            "SourceImage|endswith": "\\rundll32.exe",
            "CallTrace|contains": "comsvcs.dll",
        },
        "condition": "selection",
    },
}

POSITIVE = {"TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
            "CallTrace": "C:\\Windows\\system32\\comsvcs.dll+0x1234"}
NEG_WRONG_SOURCE = {**POSITIVE, "SourceImage": "C:\\Windows\\System32\\notepad.exe"}
NEG_MISSING_FIELD = {"TargetImage": "C:\\Windows\\System32\\lsass.exe"}   # no SourceImage / CallTrace


def test_from_sigma_parses_the_three_clauses():
    g = from_sigma(COMSVCS_RULE)
    assert g.rule_id == "test-comsvcs"
    assert len(g.selection) == 3 and not g.suppressions
    fields = {m.field: m for m in g.selection}
    assert fields["TargetImage"].op == "endswith"
    assert fields["CallTrace"].op == "contains"
    assert fields["CallTrace"].values == ("comsvcs.dll",)
    assert g.fields() == ["CallTrace", "SourceImage", "TargetImage"]


def test_cid_is_stable_and_structural():
    a, b = from_sigma(COMSVCS_RULE), from_sigma(COMSVCS_RULE)
    assert a.cid == b.cid and len(a.cid) == 64                     # same construction → same CID
    perturbed = MotifGraph(a.rule_id, a.selection[:2], a.suppressions)
    assert perturbed.cid != a.cid                                  # different molecule-set → different CID


def test_python_emitter_matches_sigma_eval():
    g = from_sigma(COMSVCS_RULE)
    for ev in (POSITIVE, NEG_WRONG_SOURCE, NEG_MISSING_FIELD):
        assert eval_python(g, ev) == evaluate_rule(COMSVCS_RULE, ev)["fires"]


@pytest.mark.skipif(not _have_corpus, reason="rdflib [rdf] extra exercised via the corpus tests")
def test_two_emitters_agree_on_crafted_events():
    g = from_sigma(COMSVCS_RULE)
    assert eval_python(g, POSITIVE) is True and eval_sparql(g, POSITIVE) is True
    for ev in (NEG_WRONG_SOURCE, NEG_MISSING_FIELD):
        assert eval_python(g, ev) is False and eval_sparql(g, ev) is False


def test_to_sparql_is_an_ask_over_referenced_fields():
    q = to_sparql(from_sigma(COMSVCS_RULE))
    assert q.startswith("PREFIX mev:") and "ASK {" in q
    assert q.count("FILTER(") == 3 and "STRENDS" in q and "CONTAINS" in q


@pytest.mark.skipif(not _have_corpus, reason="rdflib [rdf] extra not exercised without corpus")
def test_to_rdf_emits_a_detection_with_three_field_matches():
    from rdflib import RDF, Namespace
    M = Namespace("urn:canon:motif#")
    g = to_rdf(from_sigma(COMSVCS_RULE))
    dets = list(g.subjects(RDF.type, M.Detection))
    assert len(dets) == 1
    assert len(list(g.subjects(RDF.type, M.FieldMatch))) == 3


@pytest.mark.skipif(not _have_corpus, reason="OTRF corpus / SigmaHQ rules not present")
def test_emitters_agree_on_otrf_corpus():
    """The gate: Python and SPARQL emitters must agree on every event in the real corpus."""
    rule = next(r for p, r in gather("T1003.001") if "comsvcs" in p.name)
    g = from_sigma(rule)
    events = load_sysmon_events(str(OTRF))
    att = attest_emitter_agreement(g, events)
    assert att["coverage"] == "true", att["disagreements"][:3]
    assert att["n_events"] == len(events) and not att["disagreements"]
    assert len(att["evidence_cid"]) == 64


@pytest.mark.skipif(not _have_corpus, reason="OTRF corpus not present")
def test_emitter_fires_on_the_labeled_positive():
    rule = next(r for p, r in gather("T1003.001") if "comsvcs" in p.name)
    g = from_sigma(rule)
    events = load_sysmon_events(str(OTRF))
    assert sum(eval_python(g, e) for e in events) >= 1            # at least the labeled comsvcs read


@pytest.mark.skipif(not _have_corpus, reason="OTRF corpus not present")
def test_selector_provenance_closes_the_hole():
    """The ground-truth selector is recorded as a prov:Activity; the label carries its own how."""
    from rdflib import RDF

    from provenance import lineage
    from provenance.rdf import OP, to_prov

    positive = record_selector_provenance(str(OTRF))
    # the activity exists, names the op, and content-addresses the selector source
    act = positive.producer
    assert act.op_name == "comsvcs_positive_select"
    assert any(k == "selector_cid" and len(v) == 64 for k, v in act.params)
    # PROV-O emission types the activity by its op (dual-typing) and re-running selects the real instance
    g = to_prov(positive)
    assert OP["comsvcs_positive_select"] in set(g.objects(predicate=RDF.type))   # activity dual-typed by its op
    assert len(lineage(positive)) >= 2                            # positive ← selector activity ← corpus
    inst = positive.value()
    assert inst is not None and "lsass" in str(inst.get("TargetImage", "")).lower()
