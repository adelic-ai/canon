"""Ingest joint tests — validity PASS/XFAIL, and the decode's honest (liftable) guarantee.

The ingest boundary is where raw bytes become a typed Signal. Two things are under test:

* the **validity** check is a real schema predicate that bites (one PASS, two XFAIL — one per
  constraint), and the decode op refuses to emit a Signal from a payload that fails it;
* the decode's **guarantee posture** is honest *and* liftable: by default the missing
  machine-checked proof is a **recorded absence** that demotes the decode to ``well_formed``
  (so a detection downstream is capped, honestly), and supplying the proof lifts it to its
  ``machine_checked`` ceiling — which lifts the end-to-end cap with no other change.
"""

from __future__ import annotations

import numpy as np
import pytest

from forge_core.ingest import (
    DECODE_TIER_CEILING,
    decode_float64_stream,
    decode_guarantee_posture,
    validate_float64_stream,
)
from forge_core.signal import Signal, SignalKind
from provenance import (
    FALSE,
    NONE,
    TRUE,
    Tier,
    derive,
    guarantee,
    source,
)


def _stream(n_samples: int) -> bytes:
    """``n_samples`` float64s as raw little-endian bytes — a well-formed stream."""
    return np.arange(n_samples, dtype=np.float64).tobytes()


# ── validity: one PASS, two XFAIL (one per constraint) ───────────────────────


def test_well_formed_stream_is_valid():
    v = validate_float64_stream(_stream(32), min_samples=21)
    assert v.verdict == TRUE and v.deviation == ()


def test_misaligned_length_is_malformed_with_deviation():
    # 12 bytes is not a multiple of 8 → a truncated float64 stream, never a silent drop.
    v = validate_float64_stream(b"\x00" * 12, min_samples=1)
    assert v.verdict == FALSE
    assert v.deviation and "not a multiple of 8" in v.deviation[0]


def test_too_few_samples_is_malformed_with_deviation():
    # Byte-aligned (16 bytes = 2 samples) but below the declared minimum window.
    v = validate_float64_stream(_stream(2), min_samples=21)
    assert v.verdict == FALSE
    assert v.deviation and "below the required minimum window" in v.deviation[0]


# ── decode op: faithful on valid input, refuses malformed ────────────────────


def test_decode_produces_a_real_signal_from_valid_bytes():
    raw = _stream(32)
    sig = decode_float64_stream(source(raw, evidence=True), fs=2.0, min_samples=21)
    out = sig.value()  # lazy until now
    assert isinstance(out, Signal) and out.kind is SignalKind.REAL
    assert out.fs == 2.0
    np.testing.assert_array_equal(out.samples, np.arange(32, dtype=np.float64))


def test_decode_refuses_to_evaluate_a_malformed_payload():
    # The decode never emits a bogus Signal — a malformed source is routed via validity, not decoded.
    sig = decode_float64_stream(source(b"\x00" * 12, evidence=True), min_samples=1)
    with pytest.raises(ValueError, match="declared schema"):
        sig.value()


def test_decode_is_lazy_and_content_addressed_by_schema():
    raw = _stream(32)
    a = decode_float64_stream(source(raw, evidence=True, name="x"), fs=1.0, min_samples=21)
    b = decode_float64_stream(source(raw, evidence=True, name="x"), fs=1.0, min_samples=21)
    c = decode_float64_stream(source(raw, evidence=True, name="x"), fs=2.0, min_samples=21)
    assert a.id == b.id  # same schema + same source → same node (dedup)
    assert a.id != c.id  # a different declared fs is a different decode node


# ── guarantee posture: the recorded absence, and the liftable cap ────────────


def _decode_and_detector():
    """A decode feeding a (structural) detector node — enough for the guarantee fold to walk."""
    raw = _stream(64)
    decode = decode_float64_stream(source(raw, evidence=True), min_samples=21)
    det = derive("detector", lambda s: None, (decode,))  # structural; never evaluated here
    return decode, det


def test_missing_proof_is_a_recorded_absence_that_demotes_the_decode():
    decode, det = _decode_and_detector()
    claims, monitors = decode_guarantee_posture(decode)  # proof defaults to NONE
    assert claims[decode.id] == DECODE_TIER_CEILING == Tier.MACHINE_CHECKED
    assert monitors[decode.id] == NONE  # the absence — no proof discharged

    certs = guarantee(det, claims=claims, monitors=monitors)
    cert = certs[decode.id]
    # The ceiling is claimed, but it earns only the floor — and *why* is recorded, not silent.
    assert cert.claimed == Tier.MACHINE_CHECKED
    assert cert.tier == Tier.WELL_FORMED
    assert cert.demotion is not None and cert.demotion.from_tier == Tier.MACHINE_CHECKED


def test_proof_lifts_the_decode_to_its_machine_checked_ceiling():
    decode, det = _decode_and_detector()
    claims, monitors = decode_guarantee_posture(decode, proof=TRUE)  # a discharged proof
    certs = guarantee(det, claims=claims, monitors=monitors)
    cert = certs[decode.id]
    assert cert.tier == Tier.MACHINE_CHECKED and cert.demotion is None


def test_decode_cap_is_liftable_end_to_end():
    """Weakest-link end to end: a BOUNDED detector earns only WELL_FORMED while the decode's
    proof is absent (the honest cap), and earns BOUNDED once the proof lifts the decode. The
    cap is the recorded absence of a proof, not a hardcoded floor."""
    decode, det = _decode_and_detector()

    # proof absent → decode demotes to WELL_FORMED → the BOUNDED detector is capped there.
    claims, monitors = decode_guarantee_posture(decode)
    capped = guarantee(
        det, claims={**claims, det.id: Tier.BOUNDED}, monitors={**monitors, det.id: TRUE}
    )
    assert capped[det.id].tier == Tier.WELL_FORMED

    # proof present → decode earns MACHINE_CHECKED → the meet no longer pins the detection.
    claims, monitors = decode_guarantee_posture(decode, proof=TRUE)
    lifted = guarantee(
        det, claims={**claims, det.id: Tier.BOUNDED}, monitors={**monitors, det.id: TRUE}
    )
    assert lifted[det.id].tier == Tier.BOUNDED
