"""SHACL validation tests — the PASS/XFAIL self-falsifying discipline.

Every shape ships a positive instance that must conform and a negative that must
fail. The negative is built by malforming a real PROV graph (stripping the
qualifiedAssociation that the well-formedness shape requires), so the test proves
the shape actually bites.
"""
import pytest

pytest.importorskip("pyshacl")
from rdflib.namespace import PROV  # noqa: E402

from provenance import (  # noqa: E402
    derive,
    source,
    to_prov,
    validate,
    validate_graph,
)


def _dag():
    a = source(2, name="a")
    b = source(3, name="b")
    return derive("add", lambda x, y: x + y, (a, b))


# ── PASS ─────────────────────────────────────────────────────────────────────


def test_well_formed_derivation_conforms():
    report = validate(_dag())
    assert report.conforms, report.text


def test_nullary_op_still_well_formed():
    # An op with no inputs still records a plan, so it is well-formed.
    report = validate(derive("const", lambda: 42, (), {}))
    assert report.conforms, report.text


# ── XFAIL (the shape must reject malformed provenance) ───────────────────────


def test_activity_without_plan_fails():
    g = to_prov(_dag())
    # Strip every Activity's qualifiedAssociation -> malformed provenance.
    for triple in list(g.triples((None, PROV.qualifiedAssociation, None))):
        g.remove(triple)
    report = validate_graph(g)
    assert not report.conforms


def test_custom_shape_constraint_fails():
    # Our activities carry no prov:endedAtTime; a shape requiring it must fail —
    # exercises the turtle-string shapes path and a clean negative.
    shape = """
    @prefix sh:   <http://www.w3.org/ns/shacl#> .
    @prefix prov: <http://www.w3.org/ns/prov#> .
    [] a sh:NodeShape ;
       sh:targetClass prov:Activity ;
       sh:property [ sh:path prov:endedAtTime ; sh:minCount 1 ] .
    """
    report = validate(_dag(), shapes=shape)
    assert not report.conforms


# ── report shape ─────────────────────────────────────────────────────────────


def test_report_fields_populated():
    report = validate(_dag())
    assert isinstance(report.conforms, bool)
    assert isinstance(report.text, str) and report.text
    assert report.results is not None
