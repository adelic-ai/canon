"""Fan-out detection tests — synthetic mechanics + the grain guard + real ground-truth validation.

Three things are under test:
  1. the detector fires on a fan-out and not on normal cells (synthetic, always runs);
  2. **the grain is load-bearing** — changing the time-bin width changes the materialized bucket
     artifact (the guard against the recurring ``c_bin → 1`` collapse);
  3. it detects the **labeled** password-spray sources in the real ``faker-kerberos`` corpus
     (skipped if the corpus is absent) — the payoff of moving up to real telemetry.
Plus the finding that FDR over every cell is too stringent (the T0-uses-alpha tiered-dispatch lesson).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detection.fanout import (
    bucket_fanout,
    detect_fanout,
    fanout_entropy,
    load_kerberos_events,
)
from forge_core import fdr_control

_DATA = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"


def _normal_cells(n: int) -> list[tuple[float, str, str]]:
    """n normal cells: distinct sources, one account each (fan-out entropy 0), each in its own bin."""
    return [(float(i * 1000), f"normal-{i}", "acct-A") for i in range(n)]


def _spray(at: float, n_accounts: int, src: str = "spray") -> list[tuple[float, str, str]]:
    """One source touching ``n_accounts`` distinct accounts inside a single 600 s bin — a fan-out."""
    return [(at + j, src, f"acct-{j}") for j in range(n_accounts)]


# ── mechanics: detect the fan-out, spare the normals ──────────────────────────


def test_detects_a_synthetic_fanout_and_not_normal_cells():
    events = _normal_cells(300) + _spray(5_000_000.0, 16)
    res = detect_fanout(events, grain_seconds=600, alpha=0.02)
    detected = {c.entity for c in res["detected"]}
    assert detected == {"spray"}  # the high-entropy fan-out cell, and only it


def test_fanout_entropy_reuses_the_forge_core_primitive():
    # a cell touching 4 equally-likely accounts has entropy log2(4) = 2 bits.
    cells = fanout_entropy(_spray(0.0, 4), grain_seconds=600)
    assert len(cells) == 1 and cells[0].entropy == pytest.approx(2.0)


# ── the grain guard: changing grain changes the materialized artifact ─────────


def test_changing_grain_changes_the_bucketed_stream():
    # two events 400 s apart: same bin at grain 600, different bins at grain 300.
    events = [(0.0, "h", "a"), (400.0, "h", "b")]
    coarse = bucket_fanout(events, grain_seconds=600)
    fine = bucket_fanout(events, grain_seconds=300)
    assert len(coarse) == 1 and len(fine) == 2  # the partition itself changes with grain

    # ...and so does the entropy artifact: coarse sees 2 accounts (1 bit), fine sees 1 each (0 bits).
    coarse_max = max(c.entropy for c in fanout_entropy(events, grain_seconds=600))
    fine_max = max(c.entropy for c in fanout_entropy(events, grain_seconds=300))
    assert coarse_max == pytest.approx(1.0) and fine_max == pytest.approx(0.0)


def test_zero_grain_is_rejected():
    with pytest.raises(ValueError, match="grain_seconds must be > 0"):
        bucket_fanout([(0.0, "h", "a")], grain_seconds=0)


# ── the FDR finding: a T0 sweep uses alpha, not FDR-over-all-cells ────────────


def test_fdr_over_all_cells_is_too_stringent_a_t0_sweep_uses_alpha():
    """The first-slice finding: FDR over every cell rejects nothing because the discrete conformal
    floor 1/(n+1) sits ~1/q above the BH threshold q/m. The per-cell alpha sweep detects the
    fan-out; naive FDR-over-all-cells does not. FDR belongs at the reduced-multiplicity T1 layer."""
    events = _normal_cells(500) + _spray(9_000_000.0, 16)
    res = detect_fanout(events, grain_seconds=600, alpha=0.02)
    assert any(c.entity == "spray" for c in res["detected"])  # alpha sweep catches it
    assert fdr_control(res["pvalues"], q=0.05)["n_rejected"] == 0  # BH over all cells: nothing


# ── real ground-truth validation (skipped if the corpus is absent) ────────────


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_detects_labeled_password_sprays_in_real_kerberos():
    """The payoff: on real, labeled Kerberos telemetry, account fan-out at a 10-minute grain detects
    exactly the three ground-truth password-spray source IPs — full recall, no false positives at
    alpha=1e-3 (their fan-out entropy ~4.3 bits sits in a clean gap above the population)."""
    events = load_kerberos_events(str(_DATA))  # entity = source IP, value = account (spray fan-out)
    res = detect_fanout(events, grain_seconds=600, alpha=1e-3)
    detected_sources = {c.entity for c in res["detected"]}
    labeled_spray_ips = {"10.3.27.24", "10.2.234.242", "10.5.155.7"}
    assert labeled_spray_ips <= detected_sources, "missed a labeled spray (recall)"
    assert detected_sources == labeled_spray_ips, f"false positives: {detected_sources - labeled_spray_ips}"
