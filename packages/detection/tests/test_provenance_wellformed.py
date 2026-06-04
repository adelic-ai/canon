"""SHACL enforcement on the detection verdict's provenance — the well_formed claim, made mechanical.

The well-formedness fold (PROV-O + the self-falsifying SHACL shapes) was built and already enforced on
forge-core op lineage, but never run on the *detection layer's* verdict root — so a detection verdict's
``well_formed`` tier was asserted, not earned. These tests close that: a real detection verdict's
provenance materializes to PROV-O and **conforms** (the claim is now checked), and a malformed provenance
**fails and is surfaced** (the self-falsifying property is real, not decorative). Needs the [rdf] extra.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pyshacl", reason="SHACL enforcement needs the [rdf] extra")

from rdflib.namespace import PROV  # noqa: E402

from detection._verdict import build_detection_root  # noqa: E402
from provenance import to_prov, validate, validate_graph, well_formed_shapes  # noqa: E402


def test_detection_verdict_provenance_conforms_to_the_well_formed_shapes():
    """ENFORCEMENT: the ``well_formed`` claim on a detection verdict is now mechanically checked. The
    verdict's provenance root (the same one ``emit_detection_verdict`` builds) materializes to PROV-O and
    conforms to the self-falsifying shapes — every op-firing records its qualifiedAssociation → Plan."""
    root = build_detection_root(
        "password-spray|10.0.0.1|42",
        {"entity": "10.0.0.1", "bin": 42, "technique": "T1110.003"},
    )
    report = validate(root)
    assert report.conforms, report.text  # valid detection provenance PASSES


def test_malformed_detection_provenance_fails_and_the_violation_is_surfaced():
    """The other half (no silent pass): strip the qualifiedAssociation from the detection's PROV-O and
    SHACL must FAIL, with the violation NAMED in the report — failure surfaced, not silently ignored."""
    root = build_detection_root("x", {"technique": "T1110.003"})
    g = to_prov(root)
    removed = list(g.triples((None, PROV.qualifiedAssociation, None)))
    assert removed  # there was an association to strip (the well-formed case)
    for triple in removed:
        g.remove(triple)  # malform: a prov:Activity with no association → Plan

    report = validate_graph(g, well_formed_shapes())
    assert not report.conforms  # the shape rejects malformed provenance
    assert "qualifiedAssociation" in report.text  # and says WHY (surfaced, not a silent bool)
