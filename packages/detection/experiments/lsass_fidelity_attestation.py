"""Worked example: a FidelityAttestation for the LSASS_campaign_03 cell.

This is the canon-novel artifact of the detection inversion (see
``design/self_validation_architecture.md`` and the detection-inversion design notes),
realized as a conforming instance of ``contracts/fidelity_attestation.schema.json``:
the justified-verdict substrate applied to *a rule itself* instead of an event.

It encodes the CORRECTED finding (post-commit 541ab62): the failure is scoped to the
*one generic* Sigma process_access rule the first cell tested, on *this* corpus, w.r.t.
T1003.001 — and the ``scope.not_claimed`` field explicitly disowns the over-claim
("SigmaHQ misses comsvcs") that the correction retracted, because a dedicated SigmaHQ
rule catches comsvcs via CallTrace.

CIDs here are illustrative placeholders (Mordor is a GitHub fetch, not local; the
evidence run is ``otrf_first_cell.py``). ``evaluation.tier`` is therefore ``asserted``,
not ``reproducible`` — honest: the shape is proven, the CIDs are not yet computed from
real bytes. Promoting to ``reproducible`` is exactly the next step (compute the rule /
corpus / evidence CIDs from the real artifacts so the claim re-derives).

Run: `uv run python packages/detection/experiments/lsass_fidelity_attestation.py`
"""

import json
from pathlib import Path

import jsonschema

_SCHEMA_PATH = (
    Path(__file__).parents[3] / "contracts" / "fidelity_attestation.schema.json"
)

# The corrected LSASS_campaign_03 finding, as a FidelityAttestation instance.
ATTESTATION = {
    "rule": {
        "id": "proc_access_win_lsass_uncommon_access_flag",
        "source": "SigmaHQ (local vendored snapshot)",
        # illustrative — real value = CID of the exact rule YAML bytes tested
        "version_cid": "cid:illustrative:rule:lsass_uncommon_access_flag@v1",
    },
    "corpus": {
        "id": "OTRF/Security-Datasets LSASS_campaign_03",
        # illustrative — real value = CID of the NDJSON dataset bytes
        "cid": "cid:illustrative:corpus:lsass_campaign_03",
        "event_count": 42000,
    },
    "technique": "T1003.001",
    # The generic rule MISSED the ground-truth comsvcs reader on this corpus, and the
    # ground truth is known (the dataset is labeled T1003.001; the dump occurred).
    "coverage": "false",
    "cause": {
        # The allowlist is what actually bit (GAP B in the design note) — not the
        # endswith-'10' coarse proxy (GAP A), which did NOT cause the miss on this data
        # (all three readers used 0x1410, which the suffix-match does catch).
        "kind": "allowlist",
        "detail": (
            "filter_generic allowlists C:\\Windows\\system32\\ + Program Files (there to "
            "suppress legit AV/EDR lsass readers). comsvcs MiniDump is a LOLBin: it abuses "
            "rundll32.exe, a trusted signed system32 binary, so the attack runs AS the "
            "allowlisted path. Path/identity allowlists trade FP-reduction for LOLBin-FN "
            "by construction."
        ),
        "locus": "filter_generic",
    },
    "evidence": {
        "method": (
            "allowlist-off exact-mechanism re-evaluation (GrantedAccess & PROCESS_VM_READ "
            "0x10, TargetImage=lsass) over the same corpus flagged the reader the rule "
            "suppressed"
        ),
        "flagged": [
            "rundll32.exe comsvcs.dll MiniDump on lsass.exe (1 event, statistically "
            "invisible to the volume battery)",
        ],
        # illustrative — real value = CID of the otrf_first_cell.py run output node
        "cid": "cid:illustrative:evidence:otrf_first_cell_allowlist_off",
    },
    "scope": {
        "claim": (
            "rule proc_access_win_lsass_uncommon_access_flag, on corpus OTRF "
            "LSASS_campaign_03, w.r.t. technique T1003.001"
        ),
        "not_claimed": [
            "does NOT claim SigmaHQ as a whole misses T1003.001 / comsvcs — a dedicated "
            "SigmaHQ rule catches comsvcs MiniDump via CallTrace (the 2026-06-07 "
            "correction, commit 541ab62); only the one generic process_access rule tested "
            "here was evaluated",
            "does NOT claim the endswith-'10' coarse-proxy flaw (GAP A) caused THIS miss — "
            "it is a real fidelity flaw of the rule but did not bite on this corpus (all "
            "readers used 0x1410, which the suffix-match catches)",
        ],
        "rules_not_evaluated": [
            "the 10 local lsass process_access rules / 15 T1003.001-tagged rules not run",
            "the dedicated comsvcs CallTrace rule that DOES catch this technique",
        ],
    },
    "evaluation": {
        # honest: shape proven, CIDs illustrative → asserted, not reproducible (yet)
        "tier": "asserted",
        "custody": "none",  # OTRF is an unsigned corpus
    },
    # illustrative — real value = CID of this attestation's own provenance node
    "provenance": "cid:illustrative:attestation:lsass_campaign_03_generic_rule",
}


def main() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)  # the schema itself is well-formed
    jsonschema.validate(ATTESTATION, schema)  # raises on any non-conformance

    # The discipline check: a coverage='false' verdict is FORCED to carry cause+evidence.
    stripped = {k: v for k, v in ATTESTATION.items() if k not in ("cause", "evidence")}
    try:
        jsonschema.validate(stripped, schema)
        raise SystemExit("FAIL: schema accepted a coverage=false verdict with no evidence")
    except jsonschema.ValidationError:
        pass  # expected — the opinion-with-a-hash floor is forbidden by construction

    print("OK: LSASS FidelityAttestation conforms; opinion-with-a-hash floor rejected.")
    print(f"  scope.claim   : {ATTESTATION['scope']['claim']}")
    print(f"  coverage      : {ATTESTATION['coverage']} (cause={ATTESTATION['cause']['kind']})")
    print(f"  eval.tier     : {ATTESTATION['evaluation']['tier']}  custody={ATTESTATION['evaluation']['custody']}")


if __name__ == "__main__":
    main()
