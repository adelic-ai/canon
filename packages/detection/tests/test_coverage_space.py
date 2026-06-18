"""Location coverage on the found labeled multi-detector case (comsvcs T1003.001, OTRF LSASS_campaign_03).

Asserts the verdict-as-location picture AND the wiring-contract properties: the structural primary stands on
its own; the firing rule is an independent witness carrying fidelity `true`; the misses are recorded as gaps
with causes (the adjacency map) and never downgrade the verdict (absence=NONE, recorded not penalized).
"""

from pathlib import Path

import pytest

from detection.coverage_space import lsass_location_coverage
from detection.sigma_panel import SIGMA

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"

pytestmark = pytest.mark.skipif(
    not (OTRF.exists() and SIGMA.exists()), reason="OTRF corpus / SigmaHQ rules not present")


@pytest.fixture(scope="module")
def cov():
    return lsass_location_coverage(str(OTRF))


def test_primary_stands_on_its_own(cov):
    c = cov.verdict.to_contract()
    assert c["technique"] == "T1003.001" and c["decision"] == "true"
    assert c["guarantee"]["tier"] == "well_formed"        # the structural primary's own warrant


def test_firing_witness_carries_true_fidelity(cov):
    comsvcs = [w for w in cov.witnesses if "comsvcs" in w["rule"]]
    assert comsvcs and comsvcs[0]["coverage"] == "true"   # the independent witness, fidelity-attested true


def test_misses_are_recorded_gaps_with_causes(cov):
    assert len(cov.gaps) >= 5                              # the rules that don't cover this variant
    assert all(g["coverage"] == "false" for g in cov.gaps)
    causes = {g["cause"] for g in cov.gaps}
    assert "allowlist" in causes                           # the system32-LOLBin bypass (the real gap)
    # the generic uncommon-access rule is one of the allowlist gaps
    assert any("uncommon_access" in g["rule"] and g["cause"] == "allowlist" for g in cov.gaps)


def test_gaps_do_not_downgrade_the_verdict(cov):
    # absence=NONE, recorded not penalized: the gaps exist as data, but the verdict is exactly the primary's
    # (its decision/tier are unaffected by however many rules miss the location)
    c = cov.verdict.to_contract()
    assert c["decision"] == "true" and c["guarantee"]["tier"] == "well_formed"
    assert "cross_check" not in c                          # corroboration lives on the provenance edge, not here
