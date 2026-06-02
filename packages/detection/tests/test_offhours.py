"""Off-hours detection tests — the second (temporal/circular) family, a SOFT anomaly.

The validation regime is deliberately different from fan-out's exact label match:
  * **recall** — both planted off-hours accounts are caught;
  * **specificity** — 24/7 service accounts are excluded by the circular concentration gate;
  * **precision** — *not asserted*: natural, unlabeled night activity exists, so precision is not
    cleanly identifiable on this corpus. That is a property of graded evidence, not a failure (see
    ``README.md``). Asserting exact precision here would be dishonest.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detection.offhours import (
    OFF_HOURS,
    detect_offhours,
    offhours_verdict,
    offhours_verdicts,
    run_offhours,
)
from provenance import NONE, TRUE

_DATA = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"
_SCHEMA = Path(__file__).parents[3] / "contracts" / "detection_verdict.schema.json"


def _biz(entity: str, n: int, day0: int = 0) -> list[tuple[float, str, str]]:
    """n events for a business-hours-routined account (hours 9–11), one per day."""
    return [((day0 + i) * 86400 + (9 + i % 3) * 3600 + 1800, entity, "x") for i in range(n)]


def _around_the_clock(entity: str, n: int) -> list[tuple[float, str, str]]:
    """n events spread across all 24 hours — a 24/7 service account (low circular concentration)."""
    return [(i * 86400 + (i % 24) * 3600 + 1800, entity, "x") for i in range(n)]


# ── mechanics + the concentration gate ────────────────────────────────────────


def _synthetic_population() -> list[tuple[float, str, str]]:
    # Business hours dominate the population (~98%, mirroring real telemetry), so deep-night is rare
    # and a routined human's night event is a clear upper-tail outlier.
    events: list[tuple[float, str, str]] = []
    for k in range(40):  # a large business-hours population
        events += _biz(f"biz-{k}", 30, day0=k)
    events += _biz("alice", 30)  # a routined human...
    events += [(200 * 86400 + 3 * 3600, "alice", "x"), (201 * 86400 + 2 * 3600, "alice", "x")]  # ...at night
    events += _around_the_clock("svc-monitor", 24)  # a 24/7 service account (low concentration)
    return events


def test_flags_a_routined_account_at_night_and_gates_out_24x7_service():
    res = detect_offhours(_synthetic_population(), OFF_HOURS)
    detected = {d.entity for d in res["detections"]}
    assert "alice" in detected  # business-hours routine + a deep-night event → flagged
    assert "svc-monitor" not in res["gated"]  # 24/7 account has no routine → gated out entirely
    assert "svc-monitor" not in detected


def test_short_history_accounts_are_skipped():
    # below _MIN_HISTORY events → no meaningful circular routine → never gated/flagged.
    res = detect_offhours(_biz("newbie", 3) + _biz("biz", 40), OFF_HOURS)
    assert "newbie" not in res["gated"]


# ── real ground-truth validation (skipped if the corpus is absent) ────────────


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_offhours_recall_and_service_account_specificity_on_real_kerberos():
    """Recall + specificity on real labeled data; precision deliberately NOT asserted (soft anomaly).
    Both planted off-hours accounts are caught, and no 24/7 service account is flagged (the circular
    concentration gate works). The ~18 other flagged accounts are unlabeled natural night activity —
    not false positives, just unidentifiable on this corpus."""
    detected = {d.entity for d in run_offhours(str(_DATA))["detections"]}
    labeled_offhours = {"jill.rhodes", "jason.hahn"}
    assert labeled_offhours <= detected, "missed a labeled off-hours account (recall)"
    assert not any(e.startswith("svc_") for e in detected), "a 24/7 service account leaked through"


@pytest.mark.skipif(not _DATA.exists(), reason="faker-kerberos corpus not present")
def test_offhours_verdicts_are_schema_valid_and_unattested():
    """The full loop: off-hours detections → schema-valid DetectionVerdicts, custody/trustworthiness
    NONE (unsigned corpus), decision TRUE, technique T1078."""
    verdicts = offhours_verdicts(run_offhours(str(_DATA)))
    schema = json.loads(_SCHEMA.read_text())
    assert len(verdicts) >= 2  # at least the two labeled off-hours events
    for v in verdicts:
        jsonschema.validate(v.to_contract(), schema)
        assert v.custody == NONE and v.trustworthiness == NONE
        assert v.decision == TRUE and v.technique == "T1078"


def test_offhours_verdict_w_record_grounds_who_and_when():
    res = detect_offhours(_synthetic_population(), OFF_HOURS)
    alice_det = next(d for d in res["detections"] if d.entity == "alice")
    contract = offhours_verdict(alice_det, OFF_HOURS).to_contract()
    jsonschema.validate(contract, json.loads(_SCHEMA.read_text()))
    assert contract["w_record"]["who"] == "true" and contract["w_record"]["when"] == "true"
    assert contract["technique"] == "T1078"
