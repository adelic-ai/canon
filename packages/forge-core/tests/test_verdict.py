"""The first end-to-end DetectionVerdict slice: ca_cfar → the five folds → the PINNED contract.

This is the vertical slice that proves the architecture composes. One content-addressed DAG

    raw telemetry bytes  (evidence source — the keystone in-toto product)
        └─ ingest_normalize ─→ REAL test-statistic Signal
               └─ ca_cfar ─→ detection result   (the verdict's root node)

is folded five ways (value, confidence, custody, guarantee, temporal) and projected into
``detection_verdict.schema.json``. The schema is the canonical standard; until now nothing
emitted it. Each test asserts a load-bearing property of the architecture, not just shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import numpy as np
import pytest

from forge_core.detection import ca_cfar
from forge_core.signal import Signal, SignalKind
from forge_core.verdict import assemble_verdict
from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    Confidence,
    CustodyAttestation,
    Event,
    Tier,
    Trace,
    Window,
    derive,
    evidence_digest,
    recognize,
    source,
)

_SCHEMA_PATH = (
    Path(__file__).parents[3] / "contracts" / "detection_verdict.schema.json"
)
_PD = 0.9  # assumed detection probability for the Chair–Varshney leaf weight


def _detection_dag():
    """Build the raw-bytes → normalize → ca_cfar DAG. Returns (raw_bytes, raw_src, sig, root)."""
    # A connection-rate baseline (power series, non-negative) with one beacon spike.
    rates = np.full(64, 1.0, dtype=np.float64)
    rates[40] = 50.0
    raw = rates.tobytes()  # the bytes as they would arrive at the log's point of entry

    raw_src = source(raw, evidence=True)  # keystone: src.id == evidence_digest(raw)

    def _normalize(payload: bytes) -> Signal:
        arr = np.frombuffer(payload, dtype=np.float64)
        return Signal(arr, fs=1.0, kind=SignalKind.REAL)

    sig = derive("ingest_normalize", _normalize, (raw_src,), kind="REAL")
    root = ca_cfar(sig, guard=2, train=8, pfa=1e-3)
    return raw, raw_src, sig, root


def _claims(raw_src, sig, root) -> dict:
    """Per-node guarantee claims (the fold meets weakest-link over the *computed* sub-chain).

    Claims are what each node's joint *can* provide; the earned tier is the meet down the
    computed chain. The honest claims here:

    * the detector op carries BOUNDED — CA-CFAR's analytic Pfa, conditional on the
      homogeneous-noise model (the capability).
    * ``ingest_normalize`` is WELL_FORMED — a deterministic decode is structurally valid; we
      have *not* machine-checked ``np.frombuffer``, so claiming more would be over-claiming.
    * the evidence ``source`` is **left unclaimed on purpose** — a raw input carries no rigor
      tier (its trust is the orthogonal custody axis, exercised separately and TRUE here), so
      it is tier-transparent and does not enter the meet. Pre-fix it would have dragged the
      whole chain to ABSENT; it no longer does.

    Consequence (the finding the slice surfaces): the result is capped at WELL_FORMED — not
    by the source (transparent), but by the *decode*, a real computation on the
    guarantee-critical chain. To earn BOUNDED end-to-end the ingest path must itself be
    verified; the detector's BOUNDED capability alone is not enough.
    """
    return {
        sig.id: Tier.WELL_FORMED,
        root.id: Tier.BOUNDED,
    }


def _fired_index(root) -> int:
    result = root.value()
    idx = result["indices"]
    assert idx.size == 1, f"expected exactly one detection, got {idx.tolist()}"
    return int(idx[0])


def _live_attestation(raw: bytes) -> CustodyAttestation:
    """A signed, live attestation vouching for the true content digest — keystone holds."""
    return CustodyAttestation(
        product_digest=evidence_digest(raw), signed=True, feed_live=True
    )


def _confirming_verdict(when=TRUE, monitor=TRUE, attestation=None):
    """Assemble a verdict for the standard fired detection, parameterising the per-fold leaves."""
    raw_bytes, raw_src, sig, root = _detection_dag()
    idx = _fired_index(root)
    pfa = root.value()["pfa"]
    att = attestation if attestation is not None else _live_attestation(raw_bytes)
    return assemble_verdict(
        root,
        technique="T1071.001",  # application-layer C2 beaconing
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        claims=_claims(raw_src, sig, root),
        monitors={root.id: monitor},  # homogeneous-reference-window precondition verdict
        attestations={raw_src.id: att},
        when=when,
    ), idx


def test_ca_cfar_fires_on_the_beacon_spike():
    *_, root = _detection_dag()
    assert _fired_index(root) == 40  # the deterministic spike location


def test_slice_emits_a_contract_conforming_verdict():
    """The whole point: a real detection is folded five ways and conforms to the PINNED schema."""
    raw, raw_src, sig, root = _detection_dag()
    idx = _fired_index(root)
    pfa = root.value()["pfa"]

    # temporal: was the spike inside the expected window? recognized beside the DAG.
    trace = Trace(events=(Event("beacon_spike", float(idx)),), live=frozenset({"beacon_spike"}))
    when = recognize(Window("beacon_spike", lo=idx - 1, hi=idx + 1), trace)
    assert when == TRUE

    verdict = assemble_verdict(
        root,
        technique="T1071.001",
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        claims=_claims(raw_src, sig, root),
        monitors={root.id: TRUE},
        attestations={raw_src.id: _live_attestation(raw)},
        when=when,
    )

    # The provenance field is the root node's CID — full justification walks from here.
    assert verdict.provenance == root.id
    schema = json.loads(_SCHEMA_PATH.read_text())
    jsonschema.validate(verdict.to_contract(), schema)  # raises on any non-conformance


def test_keystone_custody_is_true_for_a_signed_live_evidence_source():
    """One-hash-three-roles: evidence src.id == in-toto product digest ⇒ custody is CID equality."""
    verdict, _ = _confirming_verdict()
    assert verdict.custody == TRUE
    assert verdict.to_contract()["custody"] == "true"


def test_result_is_capped_at_well_formed_by_the_decode_not_the_source():
    """Weakest-link, end-to-end: the detector *claims* BOUNDED but earns WELL_FORMED — capped
    by the *decode* (``ingest_normalize``, a real computation), not by the raw source (which
    is tier-transparent). The capability is recorded (``claimed == BOUNDED``); the result
    honestly does not inherit it. The cap is structural (weakest-link), not a per-result
    monitor demotion — so ``demotion is None``."""
    verdict, _ = _confirming_verdict(monitor=TRUE)
    assert verdict.guarantee.claimed == Tier.BOUNDED
    assert verdict.guarantee.tier == Tier.WELL_FORMED
    assert verdict.guarantee.demotion is None
    assert verdict.to_contract()["guarantee"]["tier"] == "well_formed"


def test_root_monitor_cannot_lift_above_the_decode_cap():
    """Even a confirmed monitor on the detector leaves the earned tier WELL_FORMED: the decode
    cap dominates. To reach BOUNDED the ingest path itself must be verified. (Per-result
    *monitor* demotion is exercised directly in the provenance guarantee tests, where the
    computed chain is claimed strong enough to see it.)"""
    for monitor in (FALSE, NONE, TRUE):
        verdict, _ = _confirming_verdict(monitor=monitor)
        assert verdict.guarantee.tier == Tier.WELL_FORMED


def test_tampered_evidence_makes_custody_false():
    """A digest mismatch between the vouched product and the actual bytes = tamper ⇒ FALSE."""
    bad = CustodyAttestation(product_digest="00" * 32, signed=True, feed_live=True)
    verdict, _ = _confirming_verdict(attestation=bad)
    assert verdict.custody == FALSE
    assert verdict.to_contract()["custody"] == "false"


def test_silent_feed_makes_custody_none_not_true():
    """Feed-liveness IS custody: a silent feed is unknown, never asserted-clean."""
    silent = CustodyAttestation(
        product_digest=evidence_digest(b""), signed=True, feed_live=False
    )
    verdict, _ = _confirming_verdict(attestation=silent)
    assert verdict.custody == NONE


def test_detect_validate_disagreement_surfaces_as_both_the_soundness_alarm():
    """Detector fired (∃-detect TRUE) but the temporal pattern did not hold (∀-validate FALSE):
    the carrier fuses to BOTH — the soundness alarm, not an averaged-away 0.5."""
    # temporal verdict FALSE: the spike fell outside the expected window, on a live feed.
    verdict, idx = _confirming_verdict(when=FALSE)
    assert verdict.decision == BOTH
    assert verdict.w_record.what == TRUE  # the artifact was present
    assert verdict.w_record.when == FALSE  # but the timing did not validate
    jsonschema.validate(verdict.to_contract(), json.loads(_SCHEMA_PATH.read_text()))


def test_w_record_score_is_the_fraction_of_grounded_ws():
    """Honest aggregate: only confirmed (TRUE) W's count, so an unattributed hit scores low."""
    verdict, _ = _confirming_verdict(when=TRUE)
    # what=TRUE, when=TRUE, who/where/how default NONE ⇒ 2/5 grounded.
    assert verdict.w_record.score == pytest.approx(2 / 5)
