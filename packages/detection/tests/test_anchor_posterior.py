"""Per-anchor partial-chain posterior — log-odds accumulation with forgetting."""

from types import SimpleNamespace

import pytest

from detection.anchor_posterior import AnchorPosterior, chain_evidence
from detection.completeness import chain_completeness

HOUR = 3600.0


def _post():
    return AnchorPosterior(base_rate=0.01, decay_tau_sec=6 * HOUR)


def test_unknown_anchor_is_base_rate():
    p = _post()
    assert p.probability("dc01") == pytest.approx(0.01, abs=1e-9)


def test_observing_evidence_raises_belief_above_prior():
    p = _post()
    prior_prob = p.probability("dc01")
    p.observe("dc01", llr=3.0, time=0.0)
    assert p.probability("dc01", at=0.0) > prior_prob


def test_evidence_accumulates():
    one, two = _post(), _post()
    one.observe("dc01", llr=1.5, time=0.0)
    two.observe("dc01", llr=1.5, time=0.0)
    two.observe("dc01", llr=1.5, time=0.0)          # same time → no decay between
    assert two.score("dc01", at=0.0) > one.score("dc01", at=0.0)
    assert two._beliefs["dc01"].n_evidence == 2


def test_pressure_decays_back_toward_base_rate():
    p = _post()
    p.observe("dc01", llr=5.0, time=0.0)
    hot = p.probability("dc01", at=0.0)
    cold = p.probability("dc01", at=10_000 * HOUR)   # many tau later
    assert cold < hot
    assert cold == pytest.approx(0.01, abs=1e-3)      # returned to base rate


def test_fresh_evidence_re_raises_after_decay():
    p = _post()
    p.observe("dc01", llr=5.0, time=0.0)
    far = 10_000 * HOUR
    assert p.probability("dc01", at=far) == pytest.approx(0.01, abs=1e-3)   # decayed cold
    p.observe("dc01", llr=5.0, time=far)              # new pressure at the far time
    assert p.probability("dc01", at=far) > 0.5        # hot again


def test_ranked_orders_anchors_by_pressure():
    p = _post()
    p.observe("dc01", llr=1.0, time=0.0)
    p.observe("sqlprod", llr=4.0, time=0.0)
    p.observe("fileserver", llr=2.0, time=0.0)
    order = [a for a, _ in p.ranked(at=0.0)]
    assert order == ["sqlprod", "fileserver", "dc01"]


def test_peak_survives_decay():
    p = _post()
    b = p.observe("dc01", llr=5.0, time=0.0)
    peak = b.peak_log_odds
    p.observe("dc01", llr=-1.0, time=0.0)             # a weak/negative later piece
    assert p._beliefs["dc01"].peak_log_odds == peak   # peak is not lowered


def test_chain_evidence_is_monotone_in_reach_and_completeness():
    path = ["a", "b", "c", "d", "e"]
    full = SimpleNamespace(completeness=chain_completeness(path, path))
    partial = SimpleNamespace(completeness=chain_completeness(path, ["a", "b"]))
    assert chain_evidence(full) > chain_evidence(partial) > 0.0
    # abnormality scales it
    assert chain_evidence(full, abnormality=3.0) == pytest.approx(3.0 * chain_evidence(full))


def test_base_rate_must_be_a_probability():
    with pytest.raises(ValueError):
        AnchorPosterior(base_rate=0.0)
    with pytest.raises(ValueError):
        AnchorPosterior(base_rate=1.0)
