"""cross_check on faker-kerberos — the structural∧statistical soundness check, against the truth file.

The statistical fan-out is technique-blind; two structural signatures disambiguate it, and a
disagreement (structural says NOT this signature, statistical fired) becomes cross_check=both.
Expected counts come straight from export.truth.json:
  kerberoasting    {maria, jill, christopher, debra}        pass-the-ticket {debra, robert, amanda}
The shared fan-out flags all six, so each technique's cross-check has the other technique's
accounts as `both` alarms (debra is in both truth lists → corroborated by both).
"""

from collections import Counter
from pathlib import Path

import pytest

from detection.cross_check import (
    cross_check_verdicts,
    kerberoast_signature,
    ptt_signature,
    spray_signature,
)
from detection.fanout import PASSWORD_SPRAY, SERVICE_TICKET_FANOUT

CSV = str(Path.home() / "data/faker-kerberos/v1/export.csv")
pytestmark = pytest.mark.skipif(not Path(CSV).exists(), reason="faker-kerberos corpus not present")


def _xc(verdicts) -> Counter:
    return Counter(v.to_contract()["cross_check"] for v in verdicts)


def test_kerberoast_corroborated_and_ptt_flagged_as_both():
    c = _xc(cross_check_verdicts(CSV, binding=SERVICE_TICKET_FANOUT,
                                 signature=kerberoast_signature, technique="T1558.003"))
    assert c["true"] == 4   # maria / jill / christopher / debra: RC4 signature + outlier agree
    assert c["both"] == 2   # amanda / robert: fan-out but no RC4 → soundness alarm (really pass-the-ticket)


def test_ptt_corroborated_and_kerberoast_flagged_as_both():
    c = _xc(cross_check_verdicts(CSV, binding=SERVICE_TICKET_FANOUT,
                                 signature=ptt_signature, technique="T1550.003"))
    assert c["true"] == 3   # debra / robert / amanda: orphan-TGT fan-out + outlier agree
    assert c["both"] == 3   # maria / jill / christopher: fan-out but legit TGT → alarm (really kerberoasting)


def test_spray_corroborated_no_alarms():
    c = _xc(cross_check_verdicts(CSV, binding=PASSWORD_SPRAY, signature=spray_signature))
    assert c["true"] == 3   # the three spray IPs: failed-account fan-out + outlier agree
    assert c.get("both", 0) == 0


def test_verdict_carries_far_and_belnap_cross_check():
    verdicts = cross_check_verdicts(CSV, binding=SERVICE_TICKET_FANOUT, signature=kerberoast_signature)
    assert verdicts
    for v in verdicts:
        contract = v.to_contract()
        assert contract["cross_check"] in ("true", "false", "none", "both")
        assert contract["calibration"]["far_bound"] == SERVICE_TICKET_FANOUT.alpha
        assert contract["custody"] == "none"   # unsigned corpus — not faked
