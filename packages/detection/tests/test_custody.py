"""Earned custody — a detection over ATTESTED evidence reports custody/trustworthiness off the NONE floor.

The keystone: an evidence source's CID is its content digest, and a signed attestation vouches for that
same digest, so custody = literal CID equality (one hash, three roles). Default (no evidence) keeps the
honest unsigned-telemetry floor; a digest mismatch is FALSE (tamper); an unsigned/silent feed is NONE.
Constructive — the bytes + attestation are synthesized (no signed feed in the corpora); this proves the
fold is *earnable*, real DSSE verification is the deployment boundary (`detection.ingest.attest`).
"""

from detection._verdict import emit_detection_verdict
from detection.ingest import attest
from provenance import CustodyAttestation

EVIDENCE = b'{"EventID": 10, "TargetImage": "C:\\\\Windows\\\\System32\\\\lsass.exe"}'
PARAMS = {"entity": "svc_demo", "technique": "T1003.001"}


def _emit(**kw):
    return emit_detection_verdict("otrf.json|0", technique="T1003.001", pvalue=1e-6,
                                  params=PARAMS, **kw).to_contract()


def test_unsigned_telemetry_is_none_by_default():
    c = _emit()                                   # no evidence/attestation → the honest floor
    assert c["custody"] == "none"
    assert c["trustworthiness"] == "none"
    assert c["decision"] == "true"                # the detection still stands; only custody is NONE


def test_attested_evidence_earns_custody_true():
    c = _emit(evidence=EVIDENCE, attestation=attest(EVIDENCE))
    assert c["custody"] == "true"                 # signed + digest-matched chain
    assert c["trustworthiness"] == "true"         # custody ⊔ validity (validity unchecked → custody)
    assert c["guarantee"]["tier"] == "well_formed"


def test_digest_mismatch_is_false_tamper():
    bad = CustodyAttestation(product_digest="0" * 16, signed=True, feed_live=True)   # vouches for wrong bytes
    assert _emit(evidence=EVIDENCE, attestation=bad)["custody"] == "false"


def test_silent_feed_is_none_not_true():
    silent = attest(EVIDENCE, feed_live=False)    # live but no signer/feed → the temporal-negation signal
    assert _emit(evidence=EVIDENCE, attestation=silent)["custody"] == "none"


def test_unsigned_claim_is_none():
    assert _emit(evidence=EVIDENCE, attestation=attest(EVIDENCE, signed=False))["custody"] == "none"


def test_corroboration_composition_is_a_flagged_limit():
    # documented limit: a corroboration's unattested rule-sources tmeet NONE into custody, so a
    # corroborated+attested verdict is currently NONE (not TRUE) — pinned so it's honest, not a surprise
    corro = {"rules": ["proc_access_win_lsass_dump_comsvcs_dll.yml"], "votes": 1, "classes": 7,
             "technique": "T1003.001", "logsource": "process_access"}
    c = _emit(evidence=EVIDENCE, attestation=attest(EVIDENCE), corroboration=corro)
    assert c["custody"] == "none"
