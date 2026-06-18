"""Fidelity attestation — a reproducible coverage claim about a RULE, conforming to the contract.

Synthetic cases pin the Belnap coverage fold + schema conformance with no data; the real case reproduces
the LSASS experiment's finding (the generic process_access rule MISSES comsvcs because filter_generic — the
system32 allowlist — suppresses it; rundll32 is a system32 LOLBin) on the OTRF corpus.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from detection.fidelity import attest_fidelity

_SCHEMA = json.loads((Path(__file__).parents[3] / "contracts" / "fidelity_attestation.schema.json").read_text())

# a toy rule that fires on a lsass VM_READ that is NOT an allowlisted source
_RULE = {"id": "toy-1", "detection": {
    "selection": {"TargetImage|endswith": "lsass.exe"},
    "filter_generic": {"SourceImage|startswith": "C:\\WINDOWS\\system32\\"},
    "condition": "selection and not filter_generic"}}
_HIT = {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "SourceImage": "C:\\evil\\mimi.exe"}
_SUPPRESSED = {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "SourceImage": "C:\\WINDOWS\\system32\\rundll32.exe"}


def _attest(positives):
    a = attest_fidelity(_RULE, positives, "T1003.001", rule_bytes=json.dumps(_RULE).encode(),
                        corpus_id="toy", corpus_cid="cid:sha256:toy")
    jsonschema.validate(a, _SCHEMA)   # conforms to the contract, always
    return a


def test_caught_is_true():
    assert _attest([_HIT])["coverage"] == "true"


def test_silent_on_known_instance_is_false_with_a_cause():
    a = _attest([_SUPPRESSED])                    # a real lsass read, suppressed by the allowlist
    assert a["coverage"] == "false"
    assert a["cause"]["kind"] == "allowlist" and "filter_generic" in a["cause"]["locus"]


def test_mixed_is_both_the_soundness_alarm():
    assert _attest([_HIT, _SUPPRESSED])["coverage"] == "both"


def test_no_ground_truth_is_none_never_faked_false():
    a = _attest([])
    assert a["coverage"] == "none" and a["evaluation"]["tier"] == "absent"


def test_reproducible_tier_and_provenance_rederive():
    a, b = _attest([_HIT, _SUPPRESSED]), _attest([_HIT, _SUPPRESSED])
    assert a["evaluation"]["tier"] == "reproducible"
    assert a["evidence"]["cid"] == b["evidence"]["cid"] and a["provenance"] == b["provenance"]  # deterministic


# --- the real LSASS case (reproduces the experiment) ----------------------------------------- #

OTRF = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
GENERIC_RULE = (Path(__file__).parents[3] / "packages/semantic-cyber/data/sigma-rules/rules-threat-hunting/"
                "windows/process_access/proc_access_win_lsass_uncommon_access_flag.yml")


@pytest.mark.skipif(not (OTRF.exists() and GENERIC_RULE.exists()), reason="OTRF corpus / rule not present")
def test_generic_rule_misses_comsvcs_via_allowlist():
    import yaml

    from detection.subgraph import load_sysmon_events
    events = load_sysmon_events(str(OTRF))
    spawn = next(e for e in events if str(e.get("EventID")) == "1"
                 and "comsvcs" in str(e.get("CommandLine", "")).lower())
    comsvcs = next(e for e in events if str(e.get("EventID")) == "10"
                   and e.get("SourceProcessGUID") == spawn.get("ProcessGuid")
                   and "lsass" in str(e.get("TargetImage", "")).lower())
    rule = yaml.safe_load(GENERIC_RULE.read_text())
    a = attest_fidelity(rule, [comsvcs], "T1003.001", rule_bytes=GENERIC_RULE.read_bytes(),
                        corpus_id="OTRF/LSASS_campaign_03", corpus_cid="cid:sha256:otrf", event_count=len(events))
    jsonschema.validate(a, _SCHEMA)
    assert a["coverage"] == "false"                          # the generic rule MISSES the comsvcs dump
    assert a["cause"]["kind"] == "allowlist"        # suppressed by an allowlist filter
    assert a["evaluation"]["tier"] == "reproducible"
