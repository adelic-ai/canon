"""False-discovery-rate control — multiplicity correction across many tests (Axis B, batch level).

``conformal.py`` controls the false-alarm rate of a *single* test. But a detection battery runs
*many* tests at once — every window of a series, every candidate pair in the discovery path — and
per-test control floods: ``m`` tests at level ``alpha`` give ``m·alpha`` expected false alarms, so
a 1000-pair MI sweep at ``alpha=0.01`` yields ~10 false positives even with nothing going on. This
is the multiple-comparisons reality that showed up the moment ``windowed_mi`` ran across windows.

FDR control fixes it by bounding the **expected proportion of false positives among the
rejections** (the false-discovery proportion), not the per-test rate. The input is the *same*
calibrated p-values ``conformal_detect`` emits — so FDR is a thin batch layer on top of conformal,
not a new test.

Two procedures:

* **Benjamini–Hochberg (``"bh"``)** — controls FDR ``<= q`` under independence or positive
  regression dependence (PRDS). The default; correct for largely-independent candidate pairs.
* **Benjamini–Yekutieli (``"by"``)** — controls FDR ``<= q`` under *arbitrary* dependence, paying a
  ``H_m = Σ 1/i`` factor (more conservative). Use when the tests are strongly/unknown-ly dependent
  (e.g. overlapping sliding windows, pairs sharing a stream).

Both are exact, model-free, native Python — the same register as the conformal leg they sit on.
"""

from __future__ import annotations

import numpy as np

_METHODS = ("bh", "by")


def fdr_adjust(pvalues: np.ndarray, *, method: str = "bh") -> np.ndarray:
    """Benjamini–Hochberg (or –Yekutieli) **adjusted p-values** (q-values).

    The adjusted value of a test is the smallest FDR level at which it is rejected; comparing it
    to ``q`` is equivalent to running the step-up procedure at ``q``. Non-finite inputs (a
    no-decision window — conformal's NaN) stay ``NaN`` and are **excluded from the test count
    ``m``**: a window where nothing could be decided is not a hypothesis, so it neither dilutes
    nor inflates the correction.
    """
    if method not in _METHODS:
        raise ValueError(f"method must be one of {_METHODS}, got {method!r}")
    p_all = np.asarray(pvalues, dtype=np.float64)
    adj_all = np.full(p_all.shape, np.nan, dtype=np.float64)
    finite = np.isfinite(p_all)
    p = p_all[finite]
    m = p.size
    if m == 0:
        return adj_all

    ranks = np.arange(1, m + 1)
    c = float(np.sum(1.0 / ranks)) if method == "by" else 1.0  # H_m for BY, 1 for BH

    order = np.argsort(p)
    p_sorted = p[order]
    inflated = np.minimum(1.0, (m * c / ranks) * p_sorted)
    # enforce monotone non-decreasing q-values: adj_(i) = min over j >= i of inflated_(j).
    adj_sorted = np.minimum.accumulate(inflated[::-1])[::-1]
    adj = np.empty(m, dtype=np.float64)
    adj[order] = adj_sorted
    adj_all[finite] = adj
    return adj_all


def fdr_control(pvalues: np.ndarray, *, q: float = 0.05, method: str = "bh") -> dict:
    """Reject a set of p-values at false-discovery rate ``q`` (Benjamini–Hochberg / –Yekutieli).

    Returns a dict mirroring the detector ops' shape: ``rejected`` (bool mask), ``adjusted``
    (q-values), ``indices`` (where rejected), ``n_rejected``, ``m`` (finite tests), ``q``,
    ``method``. A test is rejected iff its adjusted p-value ``<= q`` — exactly the step-up
    procedure. Controls the *expected* false-discovery proportion at ``q``; it is a statement
    about the batch, not a guarantee about any single rejection.
    """
    if not 0.0 < q < 1.0:
        raise ValueError(f"q must be in (0, 1), got {q}")
    adjusted = fdr_adjust(pvalues, method=method)
    rejected = np.isfinite(adjusted) & (adjusted <= q)
    return {
        "rejected": rejected,
        "adjusted": adjusted,
        "indices": np.flatnonzero(rejected),
        "n_rejected": int(rejected.sum()),
        "m": int(np.isfinite(np.asarray(pvalues, dtype=np.float64)).sum()),
        "q": q,
        "method": method,
    }
