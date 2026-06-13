"""Registry dispatch — observability-gated, emitting canonical verdicts, on faker-kerberos."""

from pathlib import Path

import pytest

from forge_core import DetectionVerdict

from detection.registry import REGISTRY, corpus_fields, run_applicable

CSV = str(Path.home() / "data/faker-kerberos/v1/export.csv")
pytestmark = pytest.mark.skipif(not Path(CSV).exists(), reason="faker-kerberos corpus not present")


def test_kerberos_corpus_fires_kerberos_detectors_and_gates_cloudtrail():
    verdicts, skipped = run_applicable(CSV)
    assert all(isinstance(v, DetectionVerdict) for v in verdicts)
    techniques = {v.to_contract()["technique"] for v in verdicts}
    assert {"T1110.003", "T1558.003", "T1078", "T1550.003"} <= techniques
    # the CloudTrail detector is gated out — no userIdentity/awsRegion in a Kerberos CSV
    assert any("cloudtrail_region_sweep" in s for s in skipped)


def test_observability_gate_with_explicit_fields():
    # only the spray detector's required fields present → only it applies
    verdicts, skipped = run_applicable(CSV, fields={"Client_Address", "Account_Name"})
    assert {v.to_contract()["technique"] for v in verdicts} == {"T1110.003"}
    assert len(skipped) == len(REGISTRY) - 1


def test_skipped_detectors_are_none_not_run():
    # an empty observability surface fires nothing — everything is NONE-by-construction, not cleared
    verdicts, skipped = run_applicable(CSV, fields=set())
    assert verdicts == []
    assert len(skipped) == len(REGISTRY)


def test_corpus_fields_reads_csv_header():
    assert {"Account_Name", "Ticket_Hash", "Service_Name"} <= corpus_fields(CSV)
