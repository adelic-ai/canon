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

import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from detection.fanout import (
    PASSWORD_SPRAY,
    SERVICE_TICKET_FANOUT,
    FanoutDetection,
    bucket_fanout,
    detect_fanout,
    fanout_entropy,
    fanout_verdict,
    fanout_verdicts,
    run_binding,
)
from forge_core import Calibration, fdr_control
from provenance import BOTH, NONE, TRUE

_DATA = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"
_SCHEMA = Path(__file__).parents[3] / "contracts" / "detection_verdict.schema.json"


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
    detected = {d.cell.entity for d in res["detected"]}
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
    assert any(d.cell.entity == "spray" for d in res["detected"])  # alpha sweep catches it
    assert fdr_control(res["pvalues"], q=0.05)["n_rejected"] == 0  # BH over all cells: nothing


# ── real ground-truth validation (skipped if the corpus is absent) ────────────


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_detects_labeled_password_sprays_in_real_kerberos():
    """The payoff: on real, labeled Kerberos telemetry, account fan-out at a 10-minute grain detects
    exactly the three ground-truth password-spray source IPs — full recall, no false positives at
    alpha=1e-3 (their fan-out entropy ~4.3 bits sits in a clean gap above the population)."""
    res = run_binding(str(_DATA), PASSWORD_SPRAY)  # entity = source IP, value = account
    assert res["binding"].technique == "T1110.003"
    detected_sources = {d.cell.entity for d in res["detected"]}
    labeled_spray_ips = {"10.3.27.24", "10.2.234.242", "10.5.155.7"}
    assert labeled_spray_ips <= detected_sources, "missed a labeled spray (recall)"
    assert detected_sources == labeled_spray_ips, f"false positives: {detected_sources - labeled_spray_ips}"


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_detects_labeled_kerberoasting_in_real_kerberos():
    """The SECOND binding, the SAME detector: entity = Account_Name, value = Service_Name. Account
    service-ticket fan-out catches the four labeled Kerberoasting accounts — and, as a *class*, the
    pass-the-ticket accounts too (both are 'one account, many service tickets'). Every detection is a
    labeled anomaly: full Kerberoast recall, no false positives. Two real bindings, one detector —
    the repeated structure StreamBinding should emerge from."""
    res = run_binding(str(_DATA), SERVICE_TICKET_FANOUT)  # entity = account, value = service
    assert res["binding"].technique == "T1558.003"
    detected = {d.cell.entity for d in res["detected"]}
    kerberoast = {"maria.montgomery", "jill.rhodes", "christopher.hall", "debra.gardner"}
    # pass-the-ticket accounts share the fan-out signature (many service tickets), so they are
    # expected, not false, detections; the union is the full set of labeled service-fan-out accounts.
    service_fanout_labeled = kerberoast | {"robert.johnson", "amanda.dudley"}
    assert kerberoast <= detected, "missed a labeled Kerberoast account (recall)"
    assert detected <= service_fanout_labeled, f"false positives: {detected - service_fanout_labeled}"


# ── verdict-emission: the canonical verdict, honest about unattested custody ───


def test_fanout_verdict_is_honest_about_unattested_custody():
    """Closing the loop on synthetic data: a detected fan-out → a schema-valid DetectionVerdict that
    states both truths separately — the detection is real (decision TRUE, high score), but the input
    is an unattested CSV (custody NONE), so trust reflects that (trustworthiness NONE)."""
    res = detect_fanout(_normal_cells(300) + _spray(5_000_000.0, 16), grain_seconds=600, alpha=0.02)
    (det,) = res["detected"]  # the single sprayer cell
    verdict = fanout_verdict(det, PASSWORD_SPRAY)
    contract = verdict.to_contract()
    jsonschema.validate(contract, json.loads(_SCHEMA.read_text()))

    assert verdict.decision == TRUE  # the detection fired (kjoin(detect=TRUE, when=NONE) = TRUE)
    assert verdict.score > 0.5  # statistically meaningful — a rare cell
    assert verdict.custody == NONE  # unattested CSV: honest, not faked
    assert verdict.trustworthiness == NONE  # no custody + no validity → trust unknown
    assert contract["technique"] == "T1110.003"
    # who is grounded (the source IP); when is honestly NONE — fan-out runs no temporal ∀-validate, so it
    # does NOT claim a timing validation that never happened (the None-vs-True discipline, on our own verdict).
    assert contract["w_record"]["who"] == "true" and contract["w_record"]["when"] == "none"


def test_fanout_verdict_cross_checks_distinct_count_against_entropy():
    """The cross-check applied (MECHANICS): distinct-count is the *independent* measure vs the
    entropy/conformal detector. A detected spray cell has high distinct → agreement (cross_check TRUE,
    decision preserved). The same detection forced below the distinct threshold → BOTH (the soundness
    alarm). Operational value of a disagreement is deferred (the two are correlated, so it's rare)."""
    res = detect_fanout(_normal_cells(300) + _spray(5_000_000.0, 16), grain_seconds=600, alpha=0.02)
    (det,) = res["detected"]
    assert det.cell.distinct == 16  # the sprayer touched 16 distinct accounts — the independent measure
    assert fanout_verdict(det, PASSWORD_SPRAY).cross_check == TRUE  # distinct 16 > 5 → agrees with entropy

    # force a disagreement: same detection, distinct below the threshold → entropy says fired, count doesn't
    low = FanoutDetection(cell=replace(det.cell, distinct=3), pvalue=det.pvalue)
    verdict = fanout_verdict(low, PASSWORD_SPRAY)
    assert verdict.cross_check == BOTH  # kjoin(TRUE detect, FALSE check) = BOTH — the alarm
    contract = verdict.to_contract()
    assert contract["cross_check"] == "both"
    jsonschema.validate(contract, json.loads(_SCHEMA.read_text()))  # still schema-valid with the new field


def test_when_is_earned_only_default_none_true_only_when_a_temporal_check_runs():
    """`when` is the temporal ∀-validate verdict — EARNED-only. emit_detection_verdict defaults it to
    NONE, so a producer that runs no temporal recognize() does NOT claim a timing validation. when=TRUE
    appears ONLY when a producer passes it, having actually run a temporal check (cf. test_verdict's
    recognize slice). This locks the default so the fan-out/off-hours/coordination honesty can't regress."""
    from detection._verdict import emit_detection_verdict

    v_default = emit_detection_verdict("ref", technique="T1", pvalue=1e-3, params={})
    assert v_default.w_record.when == NONE  # no temporal check ran → honest NONE, not an asserted TRUE
    v_temporal = emit_detection_verdict("ref", technique="T1", pvalue=1e-3, params={}, when=TRUE)
    assert v_temporal.w_record.when == TRUE  # a producer that ran a temporal ∀-validate may assert it


def test_fanout_verdict_attaches_conformal_calibration():
    """The calibrator role wired: a conformal-thresholded fan-out verdict CARRIES its FAR honesty —
    method 'conformal' at the binding's alpha (distribution-free FAR ≤ alpha, marginal), attached not
    recomputed. Schema-valid with the new field."""
    res = detect_fanout(_normal_cells(300) + _spray(5_000_000.0, 16), grain_seconds=600, alpha=0.02)
    (det,) = res["detected"]
    v = fanout_verdict(det, PASSWORD_SPRAY)
    assert v.calibration == Calibration("conformal", PASSWORD_SPRAY.alpha)
    assert v.to_contract()["calibration"] == {"method": "conformal", "far_bound": PASSWORD_SPRAY.alpha}
    jsonschema.validate(v.to_contract(), json.loads(_SCHEMA.read_text()))


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_real_spray_verdicts_cross_check_agrees():
    """On real labeled sprays the two fan-out measures AGREE: every emitted verdict's cross_check is
    TRUE — distinct-count is high wherever entropy flagged (they are correlated). Agreement preserves
    the decision; a disagreement would be the rare soundness alarm, and there is none here."""
    for v in fanout_verdicts(run_binding(str(_DATA), PASSWORD_SPRAY)):
        assert v.cross_check == TRUE


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_real_spray_verdicts_are_schema_valid_and_unattested():
    """The full loop on real telemetry: every detected spray cell projects into a schema-valid
    verdict; all report custody/trustworthiness NONE (the corpus is unsigned) and decision TRUE."""
    verdicts = fanout_verdicts(run_binding(str(_DATA), PASSWORD_SPRAY))
    schema = json.loads(_SCHEMA.read_text())
    assert len(verdicts) >= 3  # the labeled spray cells
    for v in verdicts:
        jsonschema.validate(v.to_contract(), schema)
        assert v.custody == NONE and v.trustworthiness == NONE
        assert v.decision == TRUE and v.technique == "T1110.003"
