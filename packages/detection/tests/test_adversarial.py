"""Adversarial semantics corpus — correct-by-construction, exercises the semantics profile across emitters.

Two claims:
* the Python oracle is **correct** on every landmine (it conforms to the *pinned* spec, including NOT folding
  non-ASCII case);
* the Python and SPARQL emitters **agree** on every landmine *except* the one documented residual
  (``nonascii_case``: SPARQL ``LCASE`` is Unicode) — and the report localizes it exactly.
"""

import importlib.util

import pytest

from detection.adversarial import adversarial_corpus, attest_corpus

_have_rdflib = importlib.util.find_spec("rdflib") is not None


def test_corpus_is_nontrivial_and_labeled():
    cases = adversarial_corpus()
    landmines = {c.landmine for c in cases}
    assert len(landmines) >= 8                              # broad coverage of the profile
    outcomes = {c.expected for c in cases}
    assert outcomes == {True, False}                       # both match and non-match are exercised


def test_oracle_is_correct_on_every_landmine():
    """The Python oracle must compute the by-construction expected on EVERY case — conformance to the pinned
    spec. (Independent of the SPARQL emitter, so it runs without rdflib.)"""
    from detection.motif import eval_python, from_sigma

    for c in adversarial_corpus():
        assert eval_python(from_sigma(c.rule), c.event) is c.expected, (c.landmine, c.note)


@pytest.mark.skipif(not _have_rdflib, reason="rdflib [rdf] extra needed for the SPARQL emitter")
def test_emitters_agree_except_the_documented_residual():
    report = attest_corpus()
    assert report["oracle_correct"], report["incorrect"]          # no oracle bug
    # the ONLY allowed divergence is the documented SPARQL Unicode-LCASE residual, on nonascii_case
    assert report["divergent_landmines"] == ["nonascii_case"], report["divergent"]
    # and the divergence is precisely what the spec predicts: SPARQL folds É→é, the oracle does not
    row = report["by_landmine"]["nonascii_case"]
    assert row["python"] is False and row["sparql"] is True
    assert len(report["cid"]) == 64


@pytest.mark.skipif(not _have_rdflib, reason="rdflib [rdf] extra needed for the SPARQL emitter")
def test_escaped_wildcard_now_agrees():
    """Regression for the SPARQL escape-routing bug this corpus surfaced: \\* must agree across emitters."""
    report = attest_corpus()
    assert report["by_landmine"]["escaped_wildcard"]["agree"] is True
    assert report["by_landmine"]["escaped_wildcard"]["correct"] is True
