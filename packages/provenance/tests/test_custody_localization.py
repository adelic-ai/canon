"""Custody localization — the backward exoneration walk over a multi-hop chain.

A digest-consistent chain does more than say "intact": walking it backward from the bytes
canon holds EXONERATES the pure-relay hops and leaves the suspect set = {origin} ∪ {transform
hops}. A relay that corrupted-then-signed is visible (pass-through that altered content, or a
seam mismatch) → a localized FALSE. Unsigned anywhere → NONE. These tests pin each case.

Chain ordering is origin → … → ingest; the last step's product is what canon holds.
"""
from provenance import (
    FALSE,
    NONE,
    TRUE,
    CustodyStep,
    custody,
    derive,
    localize,
    source,
)


def _relay(agent: str, digest: str) -> CustodyStep:
    """A declared pass-through hop: product == its single material."""
    return CustodyStep(agent=agent, materials=(digest,), product=digest, signed=True)


# ── intact chains ─────────────────────────────────────────────────────────────────────
def test_all_passthrough_chain_is_true_and_exonerates_every_relay():
    D = "deadbeef"
    chain = (
        CustodyStep("source-host", materials=(), product=D, signed=True),  # origin emits D
        _relay("collector", D),
        _relay("forwarder", D),
    )
    loc = localize(chain, held_digest=D)
    assert loc.verdict is TRUE
    assert loc.seam_break is None
    assert loc.exonerated == ("collector", "forwarder")  # signed content-preserving relays
    assert loc.suspect == ("source-host",)  # only the origin — pre-attestation content


def test_transform_hop_stays_suspect_even_on_an_intact_chain():
    # A legitimate transform changes the digest; corruption could hide inside it, so digest
    # consistency cannot exonerate it. Suspect = {origin, the transform agent}.
    D0, D1 = "aaaa", "bbbb"
    chain = (
        CustodyStep("source-host", materials=(), product=D0, signed=True),
        CustodyStep("normalizer", materials=(D0,), product=D1, signed=True, transform=True),
        _relay("forwarder", D1),
    )
    loc = localize(chain, held_digest=D1)
    assert loc.verdict is TRUE
    assert set(loc.suspect) == {"source-host", "normalizer"}
    assert loc.exonerated == ("forwarder",)  # the only pure relay


# ── proven in-transit tamper (localized FALSE) ──────────────────────────────────────────
def test_held_bytes_not_matching_last_product_is_false():
    D = "cafe"
    chain = (CustodyStep("source-host", materials=(), product=D, signed=True), _relay("collector", D))
    loc = localize(chain, held_digest="f00d")  # canon holds something else
    assert loc.verdict is FALSE
    assert "held bytes" in loc.seam_break


def test_passthrough_that_altered_content_is_false_and_localized():
    D0, D1 = "1111", "2222"
    chain = (
        CustodyStep("source-host", materials=(), product=D0, signed=True),
        # declared pass-through (transform=False) but product != material — it altered content
        CustodyStep("collector", materials=(D0,), product=D1, signed=True),
        _relay("forwarder", D1),
    )
    loc = localize(chain, held_digest=D1)
    assert loc.verdict is FALSE
    assert "collector" in loc.seam_break
    assert "collector" in loc.suspect


def test_seam_mismatch_between_hops_is_false():
    # forwarder consumes a digest that is not the collector's product → broken chain.
    chain = (
        CustodyStep("source-host", materials=(), product="1111", signed=True),
        _relay("collector", "1111"),
        CustodyStep("forwarder", materials=("9999",), product="9999", signed=True),  # wrong material
    )
    loc = localize(chain, held_digest="9999")
    assert loc.verdict is FALSE
    assert "seam mismatch" in loc.seam_break


# ── unverifiable / empty ────────────────────────────────────────────────────────────────
def test_unsigned_hop_makes_the_chain_none_not_true():
    D = "abcd"
    chain = (
        CustodyStep("source-host", materials=(), product=D, signed=True),
        CustodyStep("collector", materials=(D,), product=D, signed=False),  # unsigned relay
    )
    loc = localize(chain, held_digest=D)
    assert loc.verdict is NONE  # unverifiable — never asserted-clean
    assert loc.exonerated == ()  # cannot exonerate anyone on an unverifiable chain


def test_empty_chain_is_none():
    loc = localize((), held_digest="abcd")
    assert loc.verdict is NONE
    assert loc.suspect == () and loc.exonerated == ()


def test_origin_is_always_a_suspect():
    # Even a flawless single-hop chain cannot clear the origin: its content predates any
    # attestation, so digest-custody can never vouch for it (that is the validity axis' job).
    D = "00ff"
    loc = localize((CustodyStep("source-host", materials=(), product=D, signed=True),), held_digest=D)
    assert loc.verdict is TRUE
    assert loc.suspect == ("source-host",)


# ── integration with the custody fold (extend, not replace) ─────────────────────────────
def test_fold_uses_a_chain_when_given_one():
    """A source with a CustodyStep chain: the fold's leaf verdict is the chain's localize
    verdict, and it propagates by tmeet to derived nodes — the keystone holds because the
    chain's last product equals the evidence source's CID."""
    payload = b"connection-rate telemetry"
    src = source(payload, evidence=True)  # src.id == evidence_digest(payload)
    chain = (
        CustodyStep("source-host", materials=(), product=src.id, signed=True),
        _relay("collector", src.id),
    )
    root = derive("detect", lambda _p: None, (src,))
    verdicts = custody(root, chains={src.id: chain})
    assert verdicts[src.id] is TRUE  # intact chain
    assert verdicts[root.id] is TRUE  # tmeet propagation


def test_fold_chain_with_broken_anchor_is_false():
    payload = b"connection-rate telemetry"
    src = source(payload, evidence=True)
    # chain's last product does NOT match the held bytes (the source CID) → tamper.
    chain = (CustodyStep("source-host", materials=(), product="not-the-digest", signed=True),)
    assert custody(src, chains={src.id: chain})[src.id] is FALSE


def test_fold_falls_back_to_none_without_a_chain_or_attestation():
    src = source(b"x", evidence=True)
    assert custody(src)[src.id] is NONE  # neither chain nor attestation
