"""Custody-fold tests — were the bytes tampered between entry and evaluation?

Covers: leaf verdicts from attestations (the keystone digest-match), tmeet composition
(tampering and unknown propagate, all-intact stays intact), feed-liveness → NONE (the §6
temporal tie), totality, and ≤_k-monotonicity of the composition.
"""
import pytest

from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    CustodyAttestation,
    custody,
    derive,
    evidence_digest,
    source,
)

K = lambda *a, **k: None  # noqa: E731 — kernels never fire; the fold is structural


def _evidence(name, payload):
    """A byte-evidence source plus a matching, signed, live attestation."""
    src = source(payload, name=name)
    att = CustodyAttestation(product_digest=evidence_digest(payload))
    return src, att


# ── the keystone: an evidence source's CID IS its payload digest (cid.md PIN 4) ──────
def test_evidence_source_id_is_payload_digest():
    src = source(b"raw-log-bytes", evidence=True)
    assert src.is_evidence
    assert src.id == evidence_digest(b"raw-log-bytes")  # one hash, three roles


def test_by_reference_source_is_not_evidence():
    src = source("x", name="feed")
    assert not src.is_evidence
    assert src.id != evidence_digest("x")  # by-reference id carries no integrity claim


def test_identical_evidence_dedups_by_content():
    # Content-addressing: same bytes -> same CID, regardless of any name.
    assert source(b"abc", evidence=True).id == source(b"abc", evidence=True, name="other").id


def test_keystone_custody_verifies_by_cid_equality():
    # The in-toto product digest the attestation vouches for IS the source's CID.
    src = source(b"payload", evidence=True)
    att = CustodyAttestation(product_digest=src.id)  # product digest == CID == digest
    assert custody(src, attestations={src.id: att})[src.id] is TRUE


def test_keystone_custody_detects_tamper_via_cid_mismatch():
    src = source(b"real-payload", evidence=True)
    forged = CustodyAttestation(product_digest=evidence_digest(b"forged-payload"))
    assert custody(src, attestations={src.id: forged})[src.id] is FALSE


# ── evidence_digest ─────────────────────────────────────────────────────────────────
def test_evidence_digest_is_sha256_hex():
    d = evidence_digest("hello")
    assert d == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert evidence_digest(b"hello") == d  # bytes and str agree


def test_evidence_digest_rejects_non_bytes():
    with pytest.raises(TypeError):
        evidence_digest(42)


# ── source leaf verdicts ────────────────────────────────────────────────────────────
def test_intact_signed_matched_is_true():
    src, att = _evidence("log", "payload-bytes")
    assert custody(src, attestations={src.id: att})[src.id] is TRUE


def test_digest_mismatch_is_false():
    src = source("real-bytes", name="log")
    att = CustodyAttestation(product_digest=evidence_digest("tampered-bytes"))
    assert custody(src, attestations={src.id: att})[src.id] is FALSE  # tampered


def test_no_attestation_is_none():
    src = source("x", name="log")
    assert custody(src)[src.id] is NONE  # no signer != data-says-fine


def test_silent_feed_is_none():
    src, _ = _evidence("log", "x")
    att = CustodyAttestation(product_digest=evidence_digest("x"), feed_live=False)
    assert custody(src, attestations={src.id: att})[src.id] is NONE  # the §6 signal


def test_unsigned_is_none():
    src, _ = _evidence("log", "x")
    att = CustodyAttestation(product_digest=evidence_digest("x"), signed=False)
    assert custody(src, attestations={src.id: att})[src.id] is NONE


# ── composition (tmeet over inputs) ─────────────────────────────────────────────────
def test_all_intact_chain_is_true():
    a, aa = _evidence("a", "aaa")
    b, ba = _evidence("b", "bbb")
    root = derive("join", K, (a, b))
    v = custody(root, attestations={a.id: aa, b.id: ba})
    assert v[root.id] is TRUE


def test_tampered_input_taints_result():
    a, aa = _evidence("a", "aaa")
    b = source("real", name="b")
    bad = CustodyAttestation(product_digest=evidence_digest("forged"))
    root = derive("join", K, (a, b))
    v = custody(root, attestations={a.id: aa, b.id: bad})
    assert v[a.id] is TRUE
    assert v[b.id] is FALSE
    assert v[root.id] is FALSE  # FALSE is absorbing — tampering propagates


def test_unknown_input_makes_result_unknown():
    a, aa = _evidence("a", "aaa")
    b = source("x", name="b")  # no attestation -> NONE
    root = derive("join", K, (a, b))
    v = custody(root, attestations={a.id: aa})
    assert v[root.id] is NONE  # one unknown link -> chain unknown


def test_deep_chain_propagates():
    a, aa = _evidence("a", "seed")
    e = a
    for i in range(3):
        e = derive(f"step{i}", K, (e,))
    v = custody(e, attestations={a.id: aa})
    assert v[e.id] is TRUE  # intact source, pure derivations -> intact


def test_no_input_derived_is_vacuous_true():
    # A derived node with no inputs ingested nothing, so nothing could be tampered.
    n = derive("const", K, (), {})
    assert custody(n)[n.id] is TRUE  # tmeet identity


# ── totality ────────────────────────────────────────────────────────────────────────
def test_verdict_for_every_node():
    a, aa = _evidence("a", "aaa")
    b, ba = _evidence("b", "bbb")
    root = derive("join", K, (a, b))
    v = custody(root, attestations={a.id: aa, b.id: ba})
    assert {a.id, b.id, root.id} == set(v)


# ── ≤_k-monotonicity of the fold (feeding a child more knowledge only moves up) ──────
def test_child_knowledge_only_raises_result():
    # As input b's custody rises NONE -> TRUE (more knowledge), the join's custody must not
    # fall in ≤_k. With a intact (TRUE): b=NONE -> join NONE; b=TRUE -> join TRUE. NONE ≤_k TRUE.
    a, aa = _evidence("a", "aaa")
    b, ba = _evidence("b", "bbb")
    root = derive("join", K, (a, b))
    join_unknown = custody(root, attestations={a.id: aa})[root.id]  # b unattested -> NONE
    join_known = custody(root, attestations={a.id: aa, b.id: ba})[root.id]
    assert join_unknown is NONE and join_known is TRUE  # rose NONE -> TRUE, up ≤_k
