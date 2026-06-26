"""Validation (L4) — the test stand's non-negotiables, measured on the projected logs: benign is correlated
(single-origin), and the attacker is NOT trivially separable (naive correlation over-fires on benign)."""

from detection.evtx_xml import _parse_event
from detection.synth.emit import project_timeline
from detection.synth.inventory import build_inventory
from detection.synth.timeline import build_timeline
from detection.synth.validate import (
    naive_correlation_flags,
    origin_ips_by_account,
    separability_report,
)

_INV = build_inventory(seed=1)


def _events(seed=8, **kw):
    acts = build_timeline(_INV, seed=seed, **kw)
    logs = project_timeline(acts, _INV)
    return [_parse_event(x) for lines in logs.values() for x in lines], acts


def test_benign_users_are_single_origin():
    """Every benign human account acts from exactly one source IP across all logs — correlated, not
    random-per-log. (Service accounts can appear from a workstation IP during the attack pivot, so this is
    asserted over benign human users.)"""
    events, _acts = _events()
    origins = origin_ips_by_account(events)
    for u in _INV.users:
        ips = origins.get(u.username)
        if ips:
            assert len(ips) == 1, f"{u.username} acted from {ips} — benign should be single-origin"


def test_naive_correlation_over_fires():
    """The naive 'same IP in a TGS + a sensitive logon' signal flags far more IPs than there are real
    campaigns — benign users trip it too. So correlation alone cannot isolate the attacker; the discriminators
    must (this is exactly what L5's join adds)."""
    events, acts = _events(benign_server_logon_p=1.0, n_kerberoasters=3)
    n_campaigns = len({a.label for a in acts if a.label})
    flagged = naive_correlation_flags(events, sensitive_hosts=_INV.sensitive_hosts())
    assert len(flagged) > n_campaigns                       # over-fires: benign IPs included


def test_separability_report_shape():
    events, acts = _events()
    rep = separability_report(events, sensitive_hosts=_INV.sensitive_hosts())
    assert rep["single_origin_accounts"] >= 1
    assert rep["naive_correlation_flagged_ips"] > len({a.label for a in acts if a.label})
