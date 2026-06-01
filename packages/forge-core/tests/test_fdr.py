"""FDR-control tests — the headline is that the false-discovery proportion is held at q.

The load-bearing test is :func:`test_false_discovery_rate_is_controlled`: with many true nulls
mixed among real signals, Benjamini–Hochberg keeps the *proportion of false positives among the
rejections* at/below q — the batch-level guarantee that makes a many-window / many-pair sweep
usable where per-test conformal alone would flood. The rest pin the textbook procedure, the
BY-is-more-conservative relationship, the NaN-exclusion, and the motivating contrast with naive
per-test thresholding.
"""

from __future__ import annotations

import numpy as np

from forge_core.fdr import fdr_adjust, fdr_control


# ── the textbook step-up procedure ────────────────────────────────────────────


def test_benjamini_hochberg_classic_example():
    # m=6, q=0.05. Critical values k/m·q = .0083,.0167,.025,.0333,.0417,.05.
    # Largest k with p_(k) <= crit is k=3 (0.01 <= 0.025); reject the three smallest.
    p = [0.005, 0.009, 0.01, 0.04, 0.06, 0.5]
    out = fdr_control(p, q=0.05, method="bh")
    assert out["n_rejected"] == 3
    assert out["indices"].tolist() == [0, 1, 2]


def test_rejection_is_adjusted_p_below_q():
    p = [0.005, 0.009, 0.01, 0.04, 0.06, 0.5]
    out = fdr_control(p, q=0.05)
    # rejected iff q-value <= q — exactly the step-up procedure.
    np.testing.assert_array_equal(out["rejected"], out["adjusted"] <= 0.05)


def test_nothing_rejected_when_all_pvalues_are_large():
    out = fdr_control([0.4, 0.6, 0.8, 0.95], q=0.05)
    assert out["n_rejected"] == 0
    assert out["indices"].size == 0


# ── adjusted p-values (q-values) ──────────────────────────────────────────────


def test_adjusted_pvalues_are_monotone_and_at_least_raw():
    p = np.array([0.005, 0.009, 0.01, 0.04, 0.06, 0.5])
    adj = fdr_adjust(p)
    assert np.all(adj >= p - 1e-12)  # adjustment never lowers a p-value
    assert np.all(adj <= 1.0)
    # monotone in the same order as the raw p-values (BH q-values preserve ranking).
    assert np.all(np.diff(adj[np.argsort(p)]) >= -1e-12)


def test_by_is_more_conservative_than_bh():
    p = [0.005, 0.009, 0.01, 0.04, 0.06, 0.5]
    bh = fdr_control(p, q=0.05, method="bh")
    by = fdr_control(p, q=0.05, method="by")
    assert by["n_rejected"] <= bh["n_rejected"]  # BY pays the H_m factor
    assert np.all(by["adjusted"][np.isfinite(by["adjusted"])] >= bh["adjusted"][np.isfinite(bh["adjusted"])] - 1e-12)


# ── NaN (no-decision) handling ────────────────────────────────────────────────


def test_nan_pvalues_are_excluded_from_the_test_count():
    # Two no-decision windows (NaN) must not count toward m or be rejected.
    out = fdr_control([0.001, np.nan, 0.002, np.nan], q=0.05)
    assert out["m"] == 2  # only the two finite p-values are hypotheses
    assert np.isnan(out["adjusted"][1]) and np.isnan(out["adjusted"][3])
    assert not out["rejected"][1] and not out["rejected"][3]


# ── the headline: empirical false-discovery-rate control ──────────────────────


def test_false_discovery_rate_is_controlled():
    """With m0 true nulls (Uniform p-values) mixed among m1 strong signals (p≈0), Benjamini–
    Hochberg holds the false-discovery proportion at/below q on average. This is the batch
    guarantee per-test conformal cannot give: it bounds false positives *among the rejections*."""
    rng = np.random.default_rng(20260601)
    q = 0.1
    m0, m1, trials = 450, 50, 400
    fdps = []
    for _ in range(trials):
        nulls = rng.uniform(0.0, 1.0, m0)  # true nulls: p ~ U(0,1), every rejection is false
        signals = rng.uniform(0.0, 1e-6, m1)  # strong alternatives
        p = np.concatenate([nulls, signals])
        is_null = np.concatenate([np.ones(m0, bool), np.zeros(m1, bool)])
        rej = fdr_control(p, q=q)["rejected"]
        n_rej = rej.sum()
        fdps.append((rej & is_null).sum() / n_rej if n_rej else 0.0)
    mean_fdp = float(np.mean(fdps))
    # E[FDP] <= q·(m0/m) = 0.1·0.9 = 0.09 under BH; assert the q bound with finite-sample slack.
    assert mean_fdp <= q + 0.01, f"mean FDP {mean_fdp:.4f} exceeded q {q}"


def test_fdr_suppresses_chance_false_alarms_that_per_test_thresholding_admits():
    """The motivating case (the MI-across-windows flood): one true detection (tiny p) among many
    nulls, with a couple of nulls landing at chance-low p≈0.02. Per-test thresholding at 0.02
    rejects the true one PLUS those chance lows; FDR at q=0.05 keeps the true detection and
    suppresses the chance false alarms."""
    p = np.array([1e-8] + [0.02, 0.03] + list(np.linspace(0.2, 0.95, 28)))  # 1 signal, 2 chance-low, 28 clear nulls
    per_test = p <= 0.02  # naive per-test FAR control at 0.02
    fdr = fdr_control(p, q=0.05)["rejected"]
    assert per_test.sum() >= 2  # naive admits the chance-low nulls
    assert fdr.sum() == 1 and fdr[0]  # FDR keeps only the true detection
