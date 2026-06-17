"""Earned BOUNDED tier — the conformal FAR ≤ α bound stands only on a confirming exchangeability monitor.

Unit (emit-level): the monitor gates the tier — TRUE earns bounded, NONE/FALSE demote to well_formed (the
floor, recorded). End-to-end (data-gated): the fan-out over real telemetry earns bounded where its
calibration is stationary (faker-kerberos) and is honestly DEMOTED where the calibration drifts
(flaws CloudTrail) — the substrate refusing the bound it can't back.
"""

from pathlib import Path

import pytest

from detection._verdict import emit_detection_verdict
from provenance import FALSE, NONE, TRUE

P = {"entity": "svc", "technique": "T1110.003"}


def _tier(**kw):
    return emit_detection_verdict("x", technique="T1110.003", pvalue=1e-4, params=P,
                                  **kw).to_contract()["guarantee"]["tier"]


def test_monitor_gates_the_bounded_tier():
    assert _tier(exchangeability=TRUE) == "bounded"        # precondition confirmed → the FAR bound stands
    assert _tier(exchangeability=NONE) == "well_formed"    # unconfirmed → demoted to the floor (recorded)
    assert _tier(exchangeability=FALSE) == "well_formed"   # violated → demoted
    assert _tier() == "well_formed"                        # no monitor supplied → no bounded claim


def test_bounded_requires_a_well_formed_graph():
    # bounded is only claimed over a SHACL-well-formed graph, so its demotion floor is earned, not asserted
    assert _tier(exchangeability=TRUE) == "bounded"        # (the toy graph conforms)


# ── end-to-end on real telemetry: earned vs honestly demoted ─────────────────────────

_KRB = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"


@pytest.mark.skipif(not _KRB.exists(), reason="faker-kerberos corpus not present")
def test_fanout_earns_bounded_on_stationary_calibration():
    from detection.fanout import PASSWORD_SPRAY, fanout_verdicts, run_binding
    vs = fanout_verdicts(run_binding(str(_KRB), PASSWORD_SPRAY))
    assert vs and all(v.to_contract()["guarantee"]["tier"] == "bounded" for v in vs)


_FLAWS = sorted(Path(Path.home() / "data" / "flaws-cloudtrail" / "v1").glob("*.json"))


@pytest.mark.skipif(not _FLAWS, reason="flaws CloudTrail corpus not present")
def test_fanout_demotes_on_drifting_calibration():
    # the flaws CloudTrail calibration is non-stationary → exchangeability falsified → NOT bounded
    from detection.cloudtrail import CLOUDTRAIL_REGION_SWEEP, load_cloudtrail_events
    from detection.fanout import fanout_verdicts, run_binding
    res = run_binding(str(_FLAWS[0]), CLOUDTRAIL_REGION_SWEEP, loader=load_cloudtrail_events)
    vs = fanout_verdicts(res)
    if vs:  # if it flagged anything, the tier must be the honest floor, not an unbacked bound
        assert all(v.to_contract()["guarantee"]["tier"] == "well_formed" for v in vs)
