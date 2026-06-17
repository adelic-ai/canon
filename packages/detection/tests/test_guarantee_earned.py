"""The guarantee tier is EARNED (SHACL-validated), not asserted.

The 2026-06-14 audit found emit_detection_verdict hardcoded tier=WELL_FORMED with no validation in the
emit path (the SHACL machinery existed but was never called). Fixed: the tier now follows
validate(root).conforms. These tests pin that it RESPONDS to the validator — it drops to ABSENT when
conformance fails — i.e. it is earned, not asserted.
"""

from pathlib import Path

import provenance
import pytest
from provenance import Tier

from detection._verdict import _earned_well_formed, build_detection_root


def test_conformant_root_earns_well_formed():
    root = build_detection_root("cloudtrail-region-sweep|x", {"entity": "x"})
    assert _earned_well_formed(root) == Tier.WELL_FORMED   # SHACL conforms → tier is earned


def test_tier_drops_to_absent_when_validation_fails(monkeypatch):
    root = build_detection_root("cloudtrail-region-sweep|x", {"entity": "x"})

    class _FailReport:
        conforms = False

    monkeypatch.setattr(provenance, "validate_graph", lambda data, shapes: _FailReport())
    # the tier FOLLOWS the validator's verdict — non-conformance (generic OR domain shapes) ⇒ ABSENT.
    # If the tier were asserted (hardcoded WELL_FORMED) this would still be WELL_FORMED. It isn't ⇒ earned.
    assert _earned_well_formed(root) == Tier.ABSENT


def test_emitted_verdict_carries_the_validated_tier():
    csv = Path.home() / "data/faker-kerberos/v1/export.csv"
    if not csv.exists():
        pytest.skip("faker-kerberos corpus not present")
    from detection.fanout import SERVICE_TICKET_FANOUT, fanout_verdicts, run_binding

    v = fanout_verdicts(run_binding(str(csv), SERVICE_TICKET_FANOUT))[0]
    # EARNED, not asserted: the root SHACL-conforms (well_formed) AND, since faker-kerberos's calibration
    # is stationary, the exchangeability monitor confirms the conformal FAR bound → the tier rises to
    # `bounded`. (On a drifting calibration the monitor would demote it back to well_formed — see
    # test_bounded.py.) Either way the tier follows the validator + monitor, never a self-certification.
    assert v.to_contract()["guarantee"]["tier"] == "bounded"
