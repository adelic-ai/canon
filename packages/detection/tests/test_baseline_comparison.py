"""Conformal vs the best trivial baselines — measuring conformal's MARGINAL value on real data.

The open question since CloudTrail: conformal *works* on faker-kerberos, but does it *beat* the simplest
statistic, or is the signal already visible without it? Measured here against the best justifiable
baselines (not a strawman): distinct-count, raw volume, distribution spread — decomposing the two things
the conformal detector stacks (the entropy *feature* and the conformal *calibration*).

Finding (locked below, on the real corpus — skips if absent): **conformal-entropy has no detection
advantage over `distinct-count > k` on this corpus.** The spray IPs touch 20 distinct accounts; no normal
IP exceeds 3 — `distinct > 5` catches all three sprays with 0 FP, the same as conformal, at a far wider
margin (17 vs entropy's 2.7). The signal is fully in the simplest statistic. Conformal's value here is
*orthogonal to detection* (automatic threshold selection + a calibrated FAR bound), not better separation.
Raw volume does NOT separate — confirming it is the *fan-out* (distinct count), not activity, that matters.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from detection.fanout import (
    PASSWORD_SPRAY,
    bucket_fanout,
    detect_by_distinct_count,
    detect_fanout,
    load_kerberos_events,
)
from forge_core import shannon_entropy

_DATA = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"
_SPRAY_IPS = {"10.3.27.24", "10.2.234.242", "10.5.155.7"}


def _per_ip_max_statistics(grain_seconds: float = 600.0) -> dict[str, dict[str, float]]:
    """Per IP, the max-over-cells of each candidate statistic (the cell most likely to trip a detector)."""
    events = load_kerberos_events(
        str(_DATA), entity_field=PASSWORD_SPRAY.entity_field, value_field=PASSWORD_SPRAY.value_field
    )
    out: dict[str, dict[str, float]] = {}
    for (ip, _b), vals in bucket_fanout(events, grain_seconds=grain_seconds).items():
        _, counts = np.unique(np.asarray(vals), return_counts=True)
        total = counts.sum()
        s = {
            "distinct": float(len(counts)),
            "volume": float(total),
            "entropy": shannon_entropy(counts),
            "spread": float(1 - counts.max() / total),
        }
        cur = out.setdefault(ip, {k: -1.0 for k in s})
        for k, v in s.items():
            cur[k] = max(cur[k], v)
    return out


def _separation(per_ip: dict[str, dict[str, float]], stat: str) -> tuple[float, float]:
    """(min over spray IPs, max over normal IPs) of a statistic — separates iff spray_min > normal_max."""
    spray = [per_ip[ip][stat] for ip in _SPRAY_IPS]
    normal = [v[stat] for ip, v in per_ip.items() if ip not in _SPRAY_IPS]
    return min(spray), max(normal)


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_distinct_count_separates_at_least_as_cleanly_as_entropy():
    """The deflating result: the trivial distinct-count separates the sprays at least as cleanly as the
    entropy feature conformal is built on — so conformal's detection contribution is unproven here."""
    per_ip = _per_ip_max_statistics()
    d_spray, d_normal = _separation(per_ip, "distinct")
    e_spray, e_normal = _separation(per_ip, "entropy")

    assert d_spray > d_normal, "distinct-count must separate the sprays"
    assert e_spray > e_normal, "entropy separates too (both work)"
    # margin, normalized by the normal ceiling, is WIDER for the trivial statistic than for entropy:
    assert (d_spray - d_normal) / d_normal >= (e_spray - e_normal) / e_normal


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_distinct_count_and_conformal_detect_the_same_sprays():
    """Equivalence on detection: `distinct > 5` and the conformal-entropy detector flag the SAME set —
    exactly the three labeled spray IPs, 0 FP. Conformal adds no detection over the trivial cut here."""
    events = load_kerberos_events(
        str(_DATA), entity_field=PASSWORD_SPRAY.entity_field, value_field=PASSWORD_SPRAY.value_field
    )
    by_count = detect_by_distinct_count(events, grain_seconds=600, threshold=5)
    conformal = {d.cell.entity for d in detect_fanout(events, grain_seconds=600, alpha=1e-3)["detected"]}
    assert by_count == _SPRAY_IPS
    assert conformal == _SPRAY_IPS
    assert by_count == conformal  # same detection, the trivial baseline needing no calibration


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_raw_volume_does_not_separate_the_sprays():
    """The fan-out (distinct count) carries the signal, not activity: a normal IP out-volumes a sprayer,
    so a raw event-count threshold cannot separate them — which is *why* distinct-count, not volume, is
    the right trivial baseline to hold conformal against."""
    per_ip = _per_ip_max_statistics()
    v_spray, v_normal = _separation(per_ip, "volume")
    assert v_spray <= v_normal  # raw volume fails to separate
