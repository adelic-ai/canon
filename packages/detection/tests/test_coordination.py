"""Coordination (MI) tests — the third detector family, MI's constructive existence-proof.

The whole corpus is synthetic and self-contained (no external dataset → these always run). The point is
not "MI detects MI-shaped data" — it is the harder claim, asserted directly below:

  1. on a corpus modelling a *mechanism* (synchronized multi-host beaconing — a shared beacon schedule),
     MI + FDR recovers **exactly** the coordinated hosts (full recall, zero false pairs);
  2. **MI beats the marginals** — on the *same* corpus the per-host marginal features (activity rate,
     activity entropy) of the coordinated hosts are statistically indistinguishable from normal hosts, so
     no single-stream (fan-out/entropy) detector can separate them;
  3. the negative control: with no shared beacon the coordinated structure is gone and MI flags nothing
     (the permutation null is not crying wolf on independent streams).

This is a *constructively validated capability*, not operational validation — the ground truth is ours by
construction. See `coordination.py` and the guarantees ledger for the deliberately-limited claim.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from detection.coordination import (
    BEACON_COORDINATION,
    coordination_verdict,
    coordination_verdicts,
    detect_coordination,
    host_marginal_features,
    synthesize_coordination_events,
)
from forge_core import Calibration
from provenance import NONE, TRUE

_SCHEMA = Path(__file__).parents[3] / "contracts" / "detection_verdict.schema.json"

# Canonical fixture (verified clean — 3 compromised pairs, 0 FP, marginals blind — across seeds 7/11/23/42/101).
_CORPUS = dict(n_normal=7, n_compromised=3, n_windows=300, rate=0.32, beacon_rate=0.15, grain_seconds=600, seed=7)
_DETECT = dict(grain_seconds=600, q=0.05, n_perm=499, seed=1000)


def _true_pairs(compromised: set[str]) -> set[tuple[str, str]]:
    return {tuple(sorted((a, b))) for a in compromised for b in compromised if a < b}


# ── (1) MI + FDR recovers exactly the coordinated hosts ───────────────────────


def test_mi_recovers_the_coordinated_hosts_and_no_others():
    events, compromised = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    detected = {tuple(sorted((d.host_a, d.host_b))) for d in res["detected"]}
    true_pairs = _true_pairs(compromised)
    assert true_pairs <= detected, f"missed a coordinated pair (recall): {true_pairs - detected}"
    assert detected == true_pairs, f"false coordinated pairs: {detected - true_pairs}"


def test_coordinated_pairs_carry_the_highest_mi():
    # the three compromised pairs are the three highest-MI pairs — the signal is in the coupling.
    events, compromised = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    top3 = {tuple(sorted((d.host_a, d.host_b))) for d in sorted(res["pairs"], key=lambda d: -d.mi)[:3]}
    assert top3 == _true_pairs(compromised)


# ── (2) the load-bearing claim: MI beats the marginals ────────────────────────


def test_the_marginals_are_blind_to_the_coordination():
    """Each coordinated host is *individually* a normal host: its activity rate and activity entropy sit
    inside the normal hosts' ranges, so no per-host threshold can separate them. Only the joint (MI) sees
    the coupling. This is what makes (1) a real capability and not teaching-to-the-test."""
    events, compromised = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    feats = host_marginal_features(res["vectors"])
    comp = [feats[h] for h in feats if h in compromised]
    norm = [feats[h] for h in feats if h not in compromised]

    for axis, label in ((0, "activity rate"), (1, "activity entropy")):
        c = [f[axis] for f in comp]
        n = [f[axis] for f in norm]
        # ranges overlap ⇒ no separating threshold exists on this marginal feature.
        assert not (max(c) < min(n) or max(n) < min(c)), f"{label} separates compromised from normal"
        # and the central tendencies are close (indistinguishable, not merely overlapping tails).
        assert abs(sum(c) / len(c) - sum(n) / len(n)) < 0.05, f"{label} means differ enough to flag"


def test_a_marginal_threshold_cannot_isolate_the_coordinated_set():
    """Concretely: the best single-stream cut (rank hosts by activity rate, take the top |compromised|)
    does NOT return the coordinated set — the marginal detector, given the answer's size, still fails."""
    events, compromised = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    feats = host_marginal_features(res["vectors"])
    top_by_rate = {h for h, _ in sorted(feats.items(), key=lambda kv: -kv[1][0])[: len(compromised)]}
    assert top_by_rate != compromised  # the marginal cut picks the wrong hosts


# ── (3) negative control: no shared beacon → no coordination flagged ──────────


def test_no_beacon_no_detection():
    # beacon_rate=0 ⇒ compromised hosts are pure independent background; the coupling is gone.
    events, _ = synthesize_coordination_events(**{**_CORPUS, "beacon_rate": 0.0})
    res = detect_coordination(events, **_DETECT)
    assert res["detected"] == []  # the permutation null does not cry wolf on independent streams


# ── verdict-emission: canonical, honest about synthetic/unattested custody ─────


def test_coordination_verdict_is_schema_valid_and_unattested():
    events, compromised = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    verdicts = coordination_verdicts(res, BEACON_COORDINATION)
    schema = json.loads(_SCHEMA.read_text())
    assert len(verdicts) == len(_true_pairs(compromised))  # one per coordinated pair
    for v in verdicts:
        jsonschema.validate(v.to_contract(), schema)
        assert v.decision == TRUE and v.technique == "T1071"
        assert v.custody == NONE and v.trustworthiness == NONE  # synthetic corpus: honest, not faked

    # the W-record grounds *who* (the pair); *when* is honestly NONE — coordination is about timing, but
    # the MI dependence is the ∃-detect, not a separate temporal ∀-validate (recognize) that ran.
    one = coordination_verdict(res["detected"][0], BEACON_COORDINATION)
    contract = one.to_contract()
    assert contract["w_record"]["who"] == "true" and contract["w_record"]["when"] == "none"


def test_coordination_verdict_carries_crosscheck_and_calibration():
    """Coverage: coordination emits the SAME justified shape — a cross_check (the independent linear
    Pearson correlation vs the non-linear MI; synchronized beaconing → positive correlation agrees → TRUE)
    and an FDR calibration (level q, since this family thresholds via Benjamini-Hochberg, not conformal)."""
    events, _ = synthesize_coordination_events(**_CORPUS)
    res = detect_coordination(events, **_DETECT)
    v = coordination_verdict(res["detected"][0], BEACON_COORDINATION)
    assert v.cross_check == TRUE  # synchronized: positive correlation agrees with the MI detection
    assert v.calibration == Calibration("fdr", BEACON_COORDINATION.q)
    c = v.to_contract()
    assert c["cross_check"] == "true"
    assert c["calibration"] == {"method": "fdr", "far_bound": BEACON_COORDINATION.q}
