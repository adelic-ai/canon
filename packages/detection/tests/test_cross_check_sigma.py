"""Sigma corroboration recorded as a PROVENANCE EDGE (not on the cross_check axis).

Corroboration is a relation to other artifacts (this verdict ⇐corroborated-by⇒ a community rule-class),
so it lives in the lineage graph as a ``sigma_corroboration`` derivation that ``prov:used`` one entity
per fired rule-class — ``to_prov``-able and SHACL-conformant. The ``cross_check`` axis stays reserved for
a within-evidence redundant-measure check, so the enriched verdict carries no ``cross_check``.
"""

from pathlib import Path

import rdflib
import pytest

from detection._verdict import build_detection_root
from detection.cross_check import lsass_dump_corroborated, sigma_corroborator
from detection.sigma_panel import SIGMA
from detection.subgraph import LSASS_DUMP, load_sysmon_events, lsass_dump_verdicts, match_pattern
from provenance import to_prov

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
CANON = rdflib.Namespace("urn:canon:prov#")

pytestmark = pytest.mark.skipif(
    not (OTRF.exists() and SIGMA.exists()), reason="OTRF corpus or SigmaHQ rules not present")


@pytest.fixture(scope="module")
def match():
    return match_pattern(LSASS_DUMP, load_sysmon_events(str(OTRF)))[0]


def test_corroborator_returns_witness_evidence(match):
    corro = sigma_corroborator("T1003.001", "process_access", leg="lsass_read")(match)
    assert corro["votes"] >= 1
    assert any("comsvcs" in n for n in corro["rules"])


def test_corroboration_is_a_provenance_edge(match):
    corro = sigma_corroborator("T1003.001", "process_access", leg="lsass_read")(match)
    root = build_detection_root("lsass|x", {"pattern": "p"}, corro)
    g = to_prov(root)
    ops = {str(o) for _s, _p, o in g.triples((None, CANON.opName, None))}
    rule_nodes = [str(o) for _s, _p, o in g.triples((None, rdflib.RDFS.label, None))
                  if str(o).startswith("sigma-rule:")]
    assert "sigma_corroboration" in ops                      # the corroboration derivation is in the graph
    assert any("comsvcs" in n for n in rule_nodes)           # the fired rule-class is a related entity (edge)


def test_corroboration_not_on_cross_check_and_tier_earned():
    c = lsass_dump_corroborated(str(OTRF))[0].to_contract()
    assert "cross_check" not in c                             # corroboration is NOT overloaded onto cross_check
    assert c["guarantee"]["tier"] == "well_formed"            # whole graph (incl. corroboration) earns the tier
    assert c["decision"] == "true"


def test_silent_panel_adds_no_edge(match):
    # a technique with no overlapping community rule corroborates nothing → the witness returns None,
    # so no sigma_corroboration node is added (the panel cannot contradict, only confirm-or-abstain)
    assert sigma_corroborator("T1110.003", "process_access", leg="lsass_read")(match) is None
    bare = lsass_dump_verdicts(str(OTRF))[0].to_contract()
    assert "cross_check" not in bare
