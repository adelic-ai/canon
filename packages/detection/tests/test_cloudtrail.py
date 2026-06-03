"""CloudTrail fan-out tests — the third binding, and the two findings the new domain surfaced.

The fan-out *mechanics* are already covered in ``test_fanout.py``; this module tests what is new:
  1. the loader turns CloudTrail JSON into the same ``(seconds, entity, value)`` contract;
  2. the trivial ``distinct-count > k`` baseline (synthetic mechanics);
  3. on the real BOTS v3 CloudTrail corpus (skipped if absent):
     - the region-sweep fan-out **signal** cleanly separates the cryptojacking credential (``web_admin``)
       from the population — the signal is real;
     - the standing conformal sweep, at the same ``alpha=1e-3`` that works on 30-day Kerberos, **does
       not fire** — a ~38-min burst yields too few cells for conformal (the honest limitation), so the
       detector emits **no verdict** (it refuses to assert what the population can't justify);
     - the trivial ``distinct-region-count > k`` baseline isolates ``web_admin`` exactly — on this
       corpus the baseline *beats* conformal, the first concrete data point on the open question.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detection.cloudtrail import (
    CLOUDTRAIL_REGION_SWEEP,
    load_cloudtrail_events,
)
from detection.fanout import (
    detect_by_distinct_count,
    detect_fanout,
    fanout_entropy,
    fanout_verdicts,
    run_binding,
)

_DATA = Path.home() / "data" / "bots-v3" / "2018" / "bots_cloudtrail.json"

# Ground truth (self-evident from the corpus, cross-checked against the BOTS v3 scenario): the
# cryptojacking credential and the count of AWS regions it sweeps with RunInstances.
_ATTACKER = "web_admin"
_REGIONS_SWEPT = 15  # all AWS regions — the maximal-entropy region fan-out


# ── the trivial baseline: synthetic mechanics ─────────────────────────────────


def test_distinct_count_baseline_flags_high_cardinality_entities():
    # one entity touches 6 distinct values in a bin; the rest touch 1 — threshold 5 flags only it.
    events = [(0.0, "sweeper", f"r{j}") for j in range(6)] + [
        (0.0, f"normal-{i}", "r0") for i in range(20)
    ]
    flagged = detect_by_distinct_count(events, grain_seconds=3600, threshold=5)
    assert flagged == {"sweeper"}


# ── the loader: CloudTrail JSON → the shared (seconds, entity, value) contract ─


@pytest.mark.skipif(not _DATA.exists(), reason="BOTS v3 CloudTrail corpus not present")
def test_loader_yields_the_shared_event_contract():
    events = load_cloudtrail_events(str(_DATA))  # defaults: entity=userIdentity, value=awsRegion
    assert events and all(
        isinstance(t, float) and isinstance(e, str) and isinstance(v, str) for t, e, v in events
    )
    # the acting-credential collapse worked: web_admin is present as an entity.
    assert _ATTACKER in {e for _t, e, _v in events}


# ── finding 1: the region-sweep signal is real and cleanly separated ──────────


@pytest.mark.skipif(not _DATA.exists(), reason="BOTS v3 CloudTrail corpus not present")
def test_region_sweep_signal_isolates_the_cryptojacking_credential():
    """``web_admin`` swept RunInstances across all 15 AWS regions → near-maximal region entropy
    (≈ log2(15) = 3.9 bits), cleanly above every other identity (≤ 1.3 bits). The signal exists and
    points at exactly the right credential — independent of whether any detector *fires* on it."""
    events = load_cloudtrail_events(str(_DATA))  # entity = credential, value = region
    cells = fanout_entropy(events, grain_seconds=CLOUDTRAIL_REGION_SWEEP.grain_seconds)
    top = max(cells, key=lambda c: c.entropy)
    assert top.entity == _ATTACKER
    others = max(c.entropy for c in cells if c.entity != _ATTACKER)
    assert top.entropy > 3.8 and top.entropy - others > 2.0  # a clean gap, not a marginal lead


# ── finding 2: conformal is underpowered on the burst → no verdict (honest) ───


@pytest.mark.skipif(not _DATA.exists(), reason="BOTS v3 CloudTrail corpus not present")
def test_conformal_sweep_is_underpowered_on_the_burst_and_emits_no_verdict():
    """The honest limitation: a ~38-minute burst bins to ~11 ``(credential, hour)`` cells, so the
    conformal floor ``1/(n+1) ≈ 0.08`` is far above ``alpha=1e-3`` — the same alpha that works on
    30-day Kerberos. The standing sweep therefore flags nothing, and ``web_admin`` (the visual
    attacker) gets a p-value well above alpha. The detector then emits **no verdict**: it does not
    assert a detection its calibration cannot justify."""
    events = load_cloudtrail_events(str(_DATA))
    res = detect_fanout(events, grain_seconds=CLOUDTRAIL_REGION_SWEEP.grain_seconds, alpha=1e-3)
    assert len(res["cells"]) < 20  # a burst, not a population — too few cells to calibrate
    assert res["detected"] == []  # the sweep fires on nothing at 1e-3

    # web_admin is the highest-entropy cell yet its conformal p-value is far above alpha (underpowered).
    by_entity = {c.entity: p for c, p in zip(res["cells"], res["pvalues"])}
    assert by_entity[_ATTACKER] > 1e-3

    # closing the loop honestly: zero detections → zero verdicts. No manufactured assertion.
    assert fanout_verdicts(run_binding(str(_DATA), CLOUDTRAIL_REGION_SWEEP, loader=load_cloudtrail_events)) == []


# ── finding 2 (cont.): the trivial baseline beats conformal on this corpus ─────


@pytest.mark.skipif(not _DATA.exists(), reason="BOTS v3 CloudTrail corpus not present")
def test_trivial_distinct_region_count_baseline_isolates_the_attacker():
    """The same cells the conformal sweep could not act on are trivially separable by a domain prior:
    no legitimate IAM principal touches >5 AWS regions in an hour. ``distinct-region-count > 5``
    isolates exactly ``web_admin`` (it swept all 15) with zero false positives — where conformal,
    correctly but uselessly here, stayed silent. The trade is explicit: distribution-free rigor
    (conformal, needs a population) vs a domain assumption (the threshold, needs none)."""
    events = load_cloudtrail_events(str(_DATA))
    flagged = detect_by_distinct_count(events, grain_seconds=CLOUDTRAIL_REGION_SWEEP.grain_seconds, threshold=5)
    assert flagged == {_ATTACKER}  # exact: full recall, zero false positives

    # ground truth: web_admin really did sweep all 15 regions (the T1496 fan-out signature).
    web_admin_regions = {v for _t, e, v in events if e == _ATTACKER}
    assert len(web_admin_regions) == _REGIONS_SWEPT
