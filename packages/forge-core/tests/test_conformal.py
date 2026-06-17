"""Conformal anomaly-detection tests — the distribution-free FAR guarantee is the headline.

The load-bearing test is :func:`test_false_alarm_rate_is_controlled_distribution_free`: on
exchangeable normal data the empirical false-alarm rate stays ``<= alpha`` regardless of the
score distribution. That property — finite-sample, model-free — is the whole reason conformal
is the FP-control leg for the IT features (entropy/KL/MI), which have no native ``Pfa``. The rest
pin the p-value construction, the realized bound, the tails, and the guarantee posture.
"""

from __future__ import annotations

import numpy as np
import pytest

from forge_core.conformal import (
    conformal_detect,
    conformal_far_bound,
    conformal_guarantee_posture,
    conformal_pvalues,
)
from forge_core.signal import Signal, SignalKind
from provenance import NONE, TRUE, Entity, Tier, derive, guarantee, source


def _real(samples):
    return Signal(np.asarray(samples, dtype=np.float64), fs=1.0, kind=SignalKind.REAL)


# ── p-value construction ──────────────────────────────────────────────────────


def test_upper_pvalue_counts_calibration_at_least_as_extreme():
    cal = np.array([1.0, 2.0, 3.0, 4.0])  # n = 4
    # s = 3.5: #{c >= 3.5} = 1 (just 4.0) → p = (1+1)/5 = 0.4
    # s = 5.0: #{c >= 5.0} = 0          → p = (1+0)/5 = 0.2 (most extreme)
    # s = 0.5: #{c >= 0.5} = 4          → p = (1+4)/5 = 1.0 (least extreme)
    p = conformal_pvalues([3.5, 5.0, 0.5], cal, tail="upper")
    np.testing.assert_allclose(p, [0.4, 0.2, 1.0])


def test_lower_tail_is_the_mirror():
    cal = np.array([1.0, 2.0, 3.0, 4.0])
    # s = 0.5: #{c <= 0.5} = 0 → p = 1/5 = 0.2 (small is extreme for lower tail)
    p = conformal_pvalues([0.5, 4.5], cal, tail="lower")
    np.testing.assert_allclose(p, [0.2, 1.0])


def test_nonfinite_score_is_no_decision_not_a_flag():
    p = conformal_pvalues([np.nan, 5.0], np.array([1.0, 2.0, 3.0]), tail="upper")
    assert np.isnan(p[0]) and np.isfinite(p[1])


def test_far_bound_is_floored_and_never_exceeds_alpha():
    assert conformal_far_bound(99, 0.1) == pytest.approx(0.1)  # ⌊100·0.1⌋/100 = 10/100
    assert conformal_far_bound(9, 0.1) == pytest.approx(0.1)  # ⌊10·0.1⌋/10 = 1/10
    assert conformal_far_bound(19, 0.1) == pytest.approx(0.1)  # ⌊20·0.1⌋/20 = 2/20
    # n=8, alpha=0.1: ⌊9·0.1⌋/9 = 0/9 = 0 (too few calibration points to resolve 0.1)
    assert conformal_far_bound(8, 0.1) == 0.0


# ── the headline guarantee: distribution-free finite-sample FAR control ───────


@pytest.mark.parametrize("dist", ["normal", "exponential", "uniform", "heavy_tail"])
def test_false_alarm_rate_is_controlled_distribution_free(dist):
    """For a fresh normal point exchangeable with calibration, P(flag) <= alpha — for ANY score
    distribution. The guarantee is **marginal** (over the joint calibration+test draw), not
    conditional on one calibration set, so we average over many fresh calibration draws: each
    trial draws its own calibration and test points from the same 'normal' distribution (every
    flag is a false alarm) and we pool the decisions. The pooled rate must stay <= alpha for all
    four distributions — the model-free control CFAR/CUSUM cannot give a bounded statistic."""
    rng = np.random.default_rng(20260601)
    alpha = 0.1
    n_cal = 199  # ⌊200·0.1⌋/200 = 20/200 = 0.1 exactly
    trials, per_trial = 600, 100

    def draw(n):
        if dist == "normal":
            return rng.standard_normal(n)
        if dist == "exponential":
            return rng.exponential(1.0, n)
        if dist == "uniform":
            return rng.uniform(0.0, 1.0, n)
        return rng.standard_t(2, n)  # heavy_tail (t with 2 dof)

    flags = total = 0
    for _ in range(trials):
        p = conformal_pvalues(draw(per_trial), draw(n_cal), tail="upper")  # fresh calibration each trial
        flags += int(np.sum(p <= alpha))
        total += per_trial
    far = flags / total  # marginal: averaged over 600 calibration draws

    # The marginal rate converges to the realized bound (0.1); pooled std ~0.0012 at 60k decisions.
    assert far <= alpha + 0.01, f"{dist}: marginal FAR {far:.4f} exceeded alpha {alpha}"
    assert far >= alpha - 0.02, f"{dist}: marginal FAR {far:.4f} implausibly below the bound"


def test_anomalies_are_caught_while_normals_are_controlled():
    rng = np.random.default_rng(7)
    cal = rng.standard_normal(199)
    normal_pt, anomaly = 0.2, 9.0  # anomaly far in the upper tail
    p = conformal_pvalues([normal_pt, anomaly], cal, tail="upper")
    assert p[1] <= 0.1 < p[0]  # the anomaly is flagged at alpha=0.1, the normal point is not


# ── the op: lazy, content-addressed, calibration as a lineage edge ────────────


def test_conformal_detect_op_flags_the_upper_tail():
    cal = np.zeros(50)  # known-normal statistic is ~0
    stat = _real([0.0, 0.0, 5.0, 0.0])  # one upper-tail spike
    det = conformal_detect(stat, calibration=cal, alpha=0.05, tail="upper")
    assert isinstance(det, Entity)  # lazy op → DAG node
    r = det.value()
    assert r["indices"].tolist() == [2]
    assert r["far_bound"] == conformal_far_bound(50, 0.05)
    assert r["n_cal"] == 50


def test_calibration_is_a_provenance_used_edge():
    from provenance import lineage

    det = conformal_detect(_real([0.0, 5.0]), calibration=np.zeros(30), alpha=0.05)
    # calibration is pulled into a `used` edge (not hashed into params), so it appears in lineage.
    assert len(lineage(det)) >= 3  # the conformal node + the statistic source + the calibration source


# ── guarantee posture: BOUNDED conditional on exchangeability ─────────────────


def _conformal_node():
    # The statistic is a source input (tier-transparent — weakest-link skips it), so the cert
    # reflects the conformal node's own posture, not an unclaimed upstream computation.
    return derive("conformal_detect", lambda s: None, (source(np.zeros(3)),))


def test_posture_demotes_without_a_confirmed_exchangeability_monitor():
    node = _conformal_node()
    claims, monitors = conformal_guarantee_posture(node)  # exchangeability defaults to NONE
    assert claims[node.id] == Tier.BOUNDED and monitors[node.id] == NONE
    cert = guarantee(node, claims=claims, monitors=monitors)[node.id]
    assert cert.claimed == Tier.BOUNDED and cert.tier == Tier.WELL_FORMED
    assert cert.demotion is not None  # recorded absence, not a silent floor


def test_confirmed_exchangeability_lets_conformal_stand_at_bounded():
    node = _conformal_node()
    claims, monitors = conformal_guarantee_posture(node, exchangeability=TRUE)
    cert = guarantee(node, claims=claims, monitors=monitors)[node.id]
    assert cert.tier == Tier.BOUNDED and cert.demotion is None


# ── exchangeability monitor (the BOUNDED-tier gate) ──────────────────────────────────
def test_exchangeability_monitor_falsifies_drift_not_stationarity():
    import numpy as np
    from forge_core import exchangeability_monitor
    from provenance import TRUE, FALSE, NONE
    rng = np.random.default_rng(7)
    stationary = rng.normal(size=300)                                   # iid → not falsified
    drift = np.concatenate([rng.normal(0, 1, 150), rng.normal(4, 1, 150)])  # mean shift halfway
    assert exchangeability_monitor(stationary) is TRUE      # no detected drift — the most an empirical check earns
    assert exchangeability_monitor(drift) is FALSE          # calibration non-stationary → exchangeability violated
    assert exchangeability_monitor(stationary[:8]) is NONE  # too few to check → recorded absence, not a pass
