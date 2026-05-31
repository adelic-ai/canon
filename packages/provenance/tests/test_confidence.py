"""Confidence-fold tests — Chair–Varshney LLR fusion + the orthogonal Belnap axis.

Covers: per-detector LLR from (Pd,Pfa), LLR summation over the DAG with None as identity,
the two-axes rule (confident disagreement => log_odds≈0 AND belnap=BOTH, NOT 0.5), the
probability link, totality, and ≤_k-monotonicity of the knowledge projection.
"""
import math

import pytest

from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    NO_EVIDENCE,
    Confidence,
    confidence,
    derive,
    source,
)

K = lambda *a, **k: None  # noqa: E731 — kernels never fire; the fold is structural


# ── per-detector leaf ───────────────────────────────────────────────────────────────
def test_fired_detector_is_true_with_positive_llr():
    c = Confidence.from_detector(True, pd=0.9, pfa=0.1)
    assert c.belnap is TRUE
    assert c.log_odds == pytest.approx(math.log(0.9 / 0.1))  # positive: evidence for


def test_silent_detector_is_false_with_negative_llr():
    c = Confidence.from_detector(False, pd=0.9, pfa=0.1)
    assert c.belnap is FALSE
    assert c.log_odds == pytest.approx(math.log(0.1 / 0.9))  # negative: evidence against


def test_bad_operating_point_rejected():
    with pytest.raises(ValueError):
        Confidence.from_detector(True, pd=1.0, pfa=0.1)


def test_probability_link():
    c = Confidence(TRUE, 0.0)
    assert c.probability == pytest.approx(0.5)
    assert Confidence(NONE, None).probability is None
    assert Confidence(TRUE, math.log(0.9 / 0.1)).probability == pytest.approx(0.9)


# ── fusion over the DAG ─────────────────────────────────────────────────────────────
def test_no_evidence_is_identity():
    a = source(1, name="a")
    n = derive("n", K, (a,))
    # only n carries evidence; the source seeds NO_EVIDENCE and must not change it.
    det = Confidence.from_detector(True, pd=0.8, pfa=0.2)
    out = confidence(n, evidence={n.id: det})
    assert out[a.id] is NO_EVIDENCE
    assert out[n.id].log_odds == pytest.approx(det.log_odds)
    assert out[n.id].belnap is TRUE


def test_agreeing_detectors_sum_llr():
    a = source(1, name="a")
    b = source(2, name="b")
    root = derive("join", K, (a, b))
    da = Confidence.from_detector(True, pd=0.9, pfa=0.1)
    db = Confidence.from_detector(True, pd=0.8, pfa=0.2)
    out = confidence(root, evidence={a.id: da, b.id: db})
    assert out[root.id].log_odds == pytest.approx(da.log_odds + db.log_odds)  # LLRs add
    assert out[root.id].belnap is TRUE  # TRUE kjoin TRUE = TRUE


def test_chain_accumulates_upstream_evidence():
    a = source(1, name="a")
    b = derive("b", K, (a,))
    c = derive("c", K, (b,))
    da = Confidence.from_detector(True, pd=0.9, pfa=0.1)
    dc = Confidence.from_detector(True, pd=0.7, pfa=0.3)
    out = confidence(c, evidence={a.id: da, c.id: dc})
    assert out[c.id].log_odds == pytest.approx(da.log_odds + dc.log_odds)


# ── the load-bearing two-axes rule (§6 ii / carrier.md) ─────────────────────────────
def test_confident_disagreement_is_both_not_half():
    # Two equally-confident detectors disagree: LLRs cancel (~0) but knowledge = BOTH.
    a = source(1, name="a")
    b = source(2, name="b")
    root = derive("join", K, (a, b))
    fires = Confidence.from_detector(True, pd=0.9, pfa=0.1)   # +log(9), TRUE
    # A GOOD detector (pd>pfa) that did NOT fire => log(0.1/0.9) = -log(9), FALSE. (Using
    # pd<pfa would be a worse-than-random detector and would NOT cancel — a real gotcha.)
    silent = Confidence.from_detector(False, pd=0.9, pfa=0.1)
    out = confidence(root, evidence={a.id: fires, b.id: silent})
    assert out[root.id].log_odds == pytest.approx(0.0)  # graded axis: looks like equipoise
    assert out[root.id].belnap is BOTH  # knowledge axis: CONTRADICTION, not genuine 0.5
    # The two axes are not redundant: probability ~0.5 yet belnap flags the conflict.
    assert out[root.id].probability == pytest.approx(0.5)


# ── totality ────────────────────────────────────────────────────────────────────────
def test_confidence_for_every_node():
    a = source(1, name="a")
    b = source(2, name="b")
    root = derive("join", K, (a, b))
    out = confidence(root, evidence={})
    assert {a.id, b.id, root.id} == set(out)
    # Equal by value (==), not identity: the root fuses NO_EVIDENCE with its children into a
    # fresh-but-equal Confidence(NONE, None). Frozen dataclass => == is structural.
    assert all(v == NO_EVIDENCE for v in out.values())  # no evidence anywhere


# ── ≤_k-monotonicity of the knowledge projection ────────────────────────────────────
def test_adding_evidence_only_raises_knowledge():
    # As an input gains a verdict (NONE -> TRUE), the join's belnap moves up ≤_k, never down.
    a = source(1, name="a")
    b = source(2, name="b")
    root = derive("join", K, (a, b))
    da = Confidence.from_detector(True, pd=0.9, pfa=0.1)
    bare = confidence(root, evidence={a.id: da})[root.id].belnap        # b: NONE -> TRUE join NONE?
    withb = confidence(root, evidence={a.id: da, b.id: da})[root.id].belnap
    # TRUE kjoin NONE = TRUE already; adding b=TRUE keeps TRUE. Knowledge never fell.
    assert bare is TRUE and withb is TRUE
