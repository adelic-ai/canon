"""The first end-to-end DetectionVerdict slice: ca_cfar → the five folds → the PINNED contract.

This is the vertical slice that proves the architecture composes. One content-addressed DAG

    raw telemetry bytes  (evidence source — the keystone in-toto product)
        └─ decode_float64_stream ─→ REAL test-statistic Signal  (validity-checked ingest joint)
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

from forge_core.conformal import conformal_detect, conformal_guarantee_posture
from forge_core.detection import ca_cfar
from forge_core.information import (
    mi_shuffle_null,
    windowed_entropy,
    windowed_kl,
    windowed_mi,
)
from forge_core.ingest import (
    decode_float64_stream,
    decode_guarantee_posture,
    validate_float64_stream,
)
from forge_core.signal import Signal, SignalKind
from forge_core.verdict import assemble_verdict
from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    VALID,
    Confidence,
    CustodyAttestation,
    CustodyStep,
    Event,
    Tier,
    Trace,
    Window,
    derive,
    evidence_digest,
    kjoin,
    localize,
    recognize,
    source,
)
from provenance.validity import _as_integrity_evidence

_STR_TO_FOUR = {"none": NONE, "true": TRUE, "false": FALSE, "both": BOTH}

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

    # The ingest boundary is a real joint now (forge_core.ingest), not a per-test lambda: it
    # validity-checks the raw bytes against the declared float64-stream schema, then decodes.
    sig = decode_float64_stream(raw_src, fs=1.0, min_samples=21)
    root = ca_cfar(sig, guard=2, train=8, pfa=1e-3)
    return raw, raw_src, sig, root


def _claims(raw_src, sig, root) -> dict:
    """Per-node guarantee claims (the fold meets weakest-link over the *computed* sub-chain).

    Claims are what each node's joint *can* provide; the earned tier is the meet down the
    computed chain. The honest claims here:

    * the detector op carries BOUNDED — CA-CFAR's analytic Pfa, conditional on the
      homogeneous-noise model (the capability).
    * the ``decode_float64_stream`` joint claims its honest *ceiling* (MACHINE_CHECKED — a
      byte-faithful reinterpret is an algebraic identity), but with no proof discharged the
      posture's monitor defaults to NONE: a **recorded absence** that demotes the decode to
      WELL_FORMED (``forge_core.ingest.decode_guarantee_posture``). Pre-joint this was a flat
      WELL_FORMED claim with the reasoning in a comment; now the unproven-ness is machine-readable.
    * the evidence ``source`` is **left unclaimed on purpose** — a raw input carries no rigor
      tier (its trust is the orthogonal custody axis, exercised separately and TRUE here), so
      it is tier-transparent and does not enter the meet. Pre-fix it would have dragged the
      whole chain to ABSENT; it no longer does.

    Consequence (the finding the slice surfaces): the result is capped at WELL_FORMED — not
    by the source (transparent), but by the *decode*, a real computation on the
    guarantee-critical chain. The cap is the recorded absence of a machine-checked proof, and
    is liftable by design (pass ``proof=TRUE`` to the posture once a proof exists); the
    detector's BOUNDED capability alone is not enough.
    """
    decode_claims, _ = decode_guarantee_posture(sig)  # ceiling MACHINE_CHECKED, demotes via NONE monitor
    return {**decode_claims, root.id: Tier.BOUNDED}


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
    by the *decode* (``decode_float64_stream``, a real computation), not by the raw source (which
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


def test_cross_check_carrier_is_both_on_disagreement_and_absent_when_no_check():
    """The cross-check (MECHANICS): a verdict can carry the kjoin of the primary ∃-detect with an
    INDEPENDENT redundant measure (a primitive in its *check* role). Agreement preserves the decision;
    disagreement → BOTH (the same soundness-alarm carrier as detect/validate); no check → field absent."""
    raw, raw_src, sig, root = _detection_dag()
    pfa = root.value()["pfa"]
    base = dict(
        technique="T1071.001",
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        claims=_claims(raw_src, sig, root),
        monitors={root.id: TRUE},
        attestations={raw_src.id: _live_attestation(raw)},
    )
    # primary ∃-detect is TRUE (the detector fired)
    assert assemble_verdict(root, check=TRUE, **base).cross_check == TRUE   # agree
    assert assemble_verdict(root, check=FALSE, **base).cross_check == BOTH  # disagree → soundness alarm
    assert assemble_verdict(root, check=NONE, **base).cross_check == TRUE   # check abstains → take primary
    v_none = assemble_verdict(root, **base)
    assert v_none.cross_check is None                      # no cross-check performed
    assert "cross_check" not in v_none.to_contract()       # absent from the contract (optional field)
    both = assemble_verdict(root, check=FALSE, **base)
    assert both.to_contract()["cross_check"] == "both"
    jsonschema.validate(both.to_contract(), json.loads(_SCHEMA_PATH.read_text()))  # schema-valid with the field


def test_w_record_score_is_the_fraction_of_grounded_ws():
    """Honest aggregate: only confirmed (TRUE) W's count, so an unattributed hit scores low."""
    verdict, _ = _confirming_verdict(when=TRUE)
    # what=TRUE, when=TRUE, who/where/how default NONE ⇒ 2/5 grounded.
    assert verdict.w_record.score == pytest.approx(2 / 5)


# ── malformed source: validity forks into both lenses, never a discard ────────────────
#
# Declared ingest schema: evidence is a float64 stream — its byte length is a multiple of 8
# and holds >= 21 samples (CA-CFAR's minimum window). A 12-byte payload violates it: either an
# innocent truncated write, OR an exploit that mangled the telemetry mid-record. The validity
# check cannot tell which — and crucially must NOT drop it.


def _malformed_source_verdict(*, what):
    """A bunk payload delivered through an INTACT, signed, live custody chain. The detector node
    keys on the schema violation; `what` is the deviation routed as a feature by the caller."""
    bad = b"\x00" * 12  # 12 bytes: not a multiple of 8 → not a valid float64 stream
    bad_src = source(bad, evidence=True)  # keystone: id == evidence_digest(bad)
    flag = derive("schema_violation_detect", lambda _p: None, (bad_src,))  # structural; never evaluated

    v = validate_float64_stream(bad, min_samples=21)  # the ingest joint's schema check
    assert v.verdict == FALSE and v.deviation  # malformed, and it carries the deviation

    # The digest chain is INTACT — the bunk was faithfully delivered (this is the hard case).
    att = CustodyAttestation(product_digest=evidence_digest(bad), signed=True, feed_live=True)

    return assemble_verdict(
        flag,
        technique="T1071.001",
        # the schema-violation detector fired on the deviation itself
        confidence_evidence={flag.id: Confidence.from_detector(True, pd=_PD, pfa=1e-3)},
        claims={flag.id: Tier.WELL_FORMED},
        monitors={flag.id: TRUE},
        attestations={bad_src.id: att},
        validity=v,
        what=what,
    )


def test_malformed_with_intact_custody_makes_trustworthiness_both():
    """The headline: faithfully delivered (digest matched) yet bunk → trustworthiness BOTH, the
    soundness alarm — corruption upstream of where digest-custody can see. custody itself stays
    TRUE: the digest IS intact. The two are separate dimensions now, not collapsed — BOTH lives
    on the derived view, not in the custody slot."""
    verdict = _malformed_source_verdict(what=TRUE)
    assert verdict.custody == TRUE  # primitive: the digest is genuinely intact
    assert verdict.validity.verdict == FALSE  # primitive: the content is bunk
    assert verdict.trustworthiness == BOTH  # derived view: the contradiction
    c = verdict.to_contract()
    assert c["custody"] == "true" and c["trustworthiness"] == "both"
    jsonschema.validate(c, json.loads(_SCHEMA_PATH.read_text()))


def test_deviation_is_surfaced_in_the_contract_not_dropped():
    """The information-loss fix: the validity deviation (the detection feature) reaches the
    emitted contract instead of being discarded when the synthesis was written into custody."""
    dev = _malformed_source_verdict(what=TRUE).to_contract()["validity"]["deviation"]
    assert dev and "not a multiple of 8" in dev[0]


def _reproduce_trust(contract: dict):
    """Recompute the derived trustworthiness view from ONLY the emitted primitive fields,
    via the actual integrity-evidence map (TRUE->NONE: valid certifies nothing)."""
    custody = _STR_TO_FOUR[contract["custody"]]
    validity_verdict = _STR_TO_FOUR[contract["validity"]["verdict"]]
    return kjoin(custody, _as_integrity_evidence(validity_verdict))


def test_trustworthiness_is_reproducible_from_emitted_primitives():
    """The guardrail (makes a hardcoded default view safe, not lock-in): every derived field
    must be reproducible from the emitted primitives. We check it across the spectrum, so a
    consumer that distrusts the default can always recompute its own from custody + validity."""
    raw, raw_src, sig, root = _detection_dag()
    _fired_index(root)
    pfa = root.value()["pfa"]
    base = dict(
        technique="T1071.001",
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        claims=_claims(raw_src, sig, root),
        monitors={root.id: TRUE},
    )
    verdicts = [
        # intact custody + valid -> TRUE ; intact + malformed -> BOTH ; tampered -> FALSE ; silent -> NONE
        assemble_verdict(root, attestations={raw_src.id: _live_attestation(raw)}, validity=VALID, **base),
        _malformed_source_verdict(what=TRUE),
        assemble_verdict(root, attestations={raw_src.id: CustodyAttestation("00" * 32, signed=True, feed_live=True)}, **base),
        assemble_verdict(root, attestations={raw_src.id: CustodyAttestation(evidence_digest(b""), signed=True, feed_live=False)}, **base),
    ]
    for v in verdicts:
        c = v.to_contract()
        assert _STR_TO_FOUR[c["trustworthiness"]] == _reproduce_trust(c)


def test_custody_localization_surface_is_present_and_reproducible_when_supplied():
    """The optional explanatory surface: a chained evidence source emits custody_localization
    (verdict/suspect/exonerated), the custody scalar equals the localization verdict (the chain
    is the binding source), and a transform hop stays suspect while relays are exonerated."""
    raw, raw_src, sig, root = _detection_dag()
    _fired_index(root)
    pfa = root.value()["pfa"]
    D = raw_src.id  # evidence source CID == the chain's terminal product (keystone)
    chain = (
        CustodyStep("source-host", materials=(), product=D, signed=True),
        CustodyStep("normalizer", materials=(D,), product=D, signed=True, transform=True),
        CustodyStep("forwarder", materials=(D,), product=D, signed=True),
    )
    loc = localize(chain, held_digest=D)
    verdict = assemble_verdict(
        root,
        technique="T1071.001",
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        claims=_claims(raw_src, sig, root),
        monitors={root.id: TRUE},
        chains={raw_src.id: chain},
        localization=loc,
    )
    assert verdict.custody == TRUE  # the chain is intact → the digest scalar is TRUE
    c = verdict.to_contract()
    cl = c["custody_localization"]
    assert _STR_TO_FOUR[cl["verdict"]] == verdict.custody  # surface verdict == the scalar
    assert "normalizer" in cl["suspect"] and "source-host" in cl["suspect"]
    assert cl["exonerated"] == ["forwarder"]
    assert "seam_break" not in cl  # intact chain → no seam break
    jsonschema.validate(c, json.loads(_SCHEMA_PATH.read_text()))


def test_custody_localization_is_optional_absent_when_not_supplied():
    """Optional, not required: a verdict without a localization omits the key and still
    conforms to the PINNED schema."""
    verdict, _ = _confirming_verdict()  # no chain / localization
    c = verdict.to_contract()
    assert "custody_localization" not in c
    jsonschema.validate(c, json.loads(_SCHEMA_PATH.read_text()))


def test_naive_kjoin_would_let_valid_content_certify_so_the_map_is_the_law():
    """Pins WHY the evidence map exists: the shorthand kjoin(custody, validity.verdict) lets a
    valid payload certify a silent chain (NONE -> TRUE) — the vindication we forbid. The real
    map (TRUE->NONE) does not. Reproduction must use the map, not the shorthand."""
    silent_custody, valid_verdict = NONE, TRUE
    naive = kjoin(silent_custody, valid_verdict)  # ChatGPT's shorthand
    real = kjoin(silent_custody, _as_integrity_evidence(valid_verdict))  # the implementation
    assert naive == TRUE  # wrong: valid content "certified" a chain with no integrity signal
    assert real == NONE  # right: valid vindicates nothing


def test_malformation_as_signature_sets_what_true_not_false():
    """When the deviation matches the technique (the malformation IS the artifact — e.g. a
    protocol violation from an exploit), `what` is TRUE. A malformed source is a detection,
    not a discard."""
    verdict = _malformed_source_verdict(what=TRUE)
    assert verdict.w_record.what == TRUE


def test_malformation_blinding_a_needed_field_sets_what_none_never_false():
    """When the malformation makes a field the detector needed unparseable, `what` is NONE
    (can't tell) — never FALSE. 'Couldn't validate' is absence of evidence, not 'didn't
    happen'; collapsing it to FALSE is the parser-evasion trap."""
    verdict = _malformed_source_verdict(what=NONE)
    assert verdict.w_record.what == NONE
    assert verdict.w_record.what != FALSE


def test_valid_source_custody_and_trustworthiness_agree_validity_vindicates_nothing():
    """A valid payload: custody (digest) and trustworthiness agree, both TRUE — and the deviation
    is empty. Validity can contest but never certify, so it never lifts trustworthiness above the
    digest verdict."""
    raw, raw_src, sig, root = _detection_dag()
    _fired_index(root)
    pfa = root.value()["pfa"]
    v = assemble_verdict(
        root,
        technique="T1071.001",
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        claims=_claims(raw_src, sig, root),
        monitors={root.id: TRUE},
        attestations={raw_src.id: _live_attestation(raw)},
        validity=VALID,
    )
    assert v.custody == TRUE
    assert v.validity.verdict == TRUE and v.validity.deviation == ()
    assert v.trustworthiness == TRUE  # equals custody — valid content adds nothing


# ── second producer: entropy × CFAR (a different FEATURE, the same test) ──────
#
# Everything above folds ONE cell: count × CFAR. This is the second cell — it swaps the
# *feature* axis (count → windowed Shannon entropy) while keeping the *test* (ca_cfar). Two
# things it pins down, the reason a careful n=2 beats hand-wiring the whole battery:
#   1. the producer pattern generalizes — a structurally different detector emits the SAME
#      canonical DetectionVerdict, validated against the same PINNED schema;
#   2. what the wiring depends on: the verdict keys on the TEST (CFAR supplies Pfa + decision),
#      not the feature. The feature only supplies the statistic Signal and, like the ingest
#      decode, is an unverified computation that caps the chain at well_formed.
# Finding surfaced while wiring it: CA-CFAR's square-law `alpha` is calibrated for large-
# dynamic-range power statistics; entropy is bounded by log2(k), so the closed-form Pfa is
# mismatched (a bounded statistic wants its own threshold calibration — a real TODO, not a bug
# here). Tuned params below give a clean single fire; the calibration question is logged, not
# papered over.


def _entropy_cfar_dag():
    """raw category-code stream (evidence) → decode → windowed_entropy → ca_cfar.

    A host that normally talks to ~1 destination (low entropy floor) then enumerates 16 distinct
    destinations in one window — a fan-out spike (Account/Network Discovery). Non-overlapping
    windows (``step=window``) so a brief enumeration is an isolated spike, not a triangular ramp
    that would contaminate CFAR's own reference cells."""
    rng = np.random.default_rng(7)
    W = 16

    def baseline(n):
        x = np.zeros(n)
        flip = rng.random(n) < 0.05  # rarely a second destination
        x[flip] = 1.0
        return x.astype(np.float64)

    codes = np.concatenate([baseline(240), np.arange(W, dtype=np.float64), baseline(240)])
    raw = codes.tobytes()
    raw_src = source(raw, evidence=True)
    sig = decode_float64_stream(raw_src, fs=1.0, min_samples=21)
    feat = windowed_entropy(sig, window=W, step=W)
    root = ca_cfar(feat, guard=2, train=8, pfa=1e-2)
    return raw, raw_src, sig, feat, root


def _entropy_verdict():
    raw, raw_src, sig, feat, root = _entropy_cfar_dag()
    pfa = root.value()["pfa"]
    decode_claims, _ = decode_guarantee_posture(sig)
    return root, assemble_verdict(
        root,
        technique="T1087",  # Account Discovery — enumeration / fan-out
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=pfa)},
        # decode (ceiling MACHINE_CHECKED, demotes) + entropy feature (WELL_FORMED) + detector (BOUNDED)
        claims={**decode_claims, feat.id: Tier.WELL_FORMED, root.id: Tier.BOUNDED},
        monitors={root.id: TRUE},
        attestations={raw_src.id: _live_attestation(raw)},
    )


def test_entropy_cfar_fires_once_on_the_fanout_spike():
    root, _ = _entropy_verdict()
    assert root.value()["indices"].tolist() == [15], "the fan-out window is the single detection"


def test_entropy_cfar_verdict_conforms_to_the_pinned_schema():
    """The second producer emits the canonical standard: a structurally different detector
    (entropy feature, not count) projects into the same detection_verdict.schema.json."""
    _, verdict = _entropy_verdict()
    jsonschema.validate(verdict.to_contract(), json.loads(_SCHEMA_PATH.read_text()))


def test_entropy_producer_wiring_matches_the_count_producer():
    """The thesis the n=2 confirms: the verdict wiring depends on the TEST, not the feature.
    Same CFAR test ⇒ same custody (keystone TRUE), same guarantee posture (BOUNDED *claimed*,
    WELL_FORMED *earned* — capped by the computed chain, here the entropy feature and the decode,
    both unverified computations), same decision projection (detect fired, no contradiction)."""
    _, verdict = _entropy_verdict()
    assert verdict.custody == TRUE                     # keystone holds — signed, live evidence
    assert verdict.guarantee.claimed == Tier.BOUNDED   # the detector's capability, recorded
    assert verdict.guarantee.tier == Tier.WELL_FORMED  # earned: capped by the unverified feature + decode
    assert verdict.decision == TRUE                    # detect fired; no temporal contradiction
    assert verdict.score > 0.0


# ── third producer: entropy × CONFORMAL (a different TEST — distribution-free FP control) ──
#
# entropy × CFAR (above) exposed that CA-CFAR's square-law alpha is mismatched to a *bounded*
# statistic. Conformal is the fix the battery design names: a distribution-free, finite-sample
# false-alarm bound, correct for ANY statistic (no noise model). This producer swaps the TEST
# axis (CFAR → conformal). It shows two things:
#   1. the verdict wiring STILL generalizes — conformal supplies a `far_bound` (a Pfa-analog) and
#      a detection decision, exactly what the confidence leaf + decision projection consume, so
#      assemble_verdict is unchanged. (Last turn's finding: the wiring keys on the test supplying
#      Pfa + decision; conformal supplies both, so it slots straight in.)
#   2. the bounded claim is now HONEST for entropy — conformal's bound has no model to mismatch;
#      its assumption is exchangeability (confirmed here via the monitor, as CFAR confirms its
#      homogeneous-window monitor). End-to-end the detection is still well_formed-capped by the
#      unverified feature + decode; what conformal fixes is the *validity* of the test's bound,
#      not the end-to-end tier.


def _entropy_conformal_verdict():
    rng = np.random.default_rng(11)
    W = 16

    def baseline(n):
        x = np.zeros(n)
        flip = rng.random(n) < 0.05
        x[flip] = 1.0
        return x.astype(np.float64)

    # calibration: entropy of a long purely-normal stream — the known-normal reference scores.
    cal = (
        windowed_entropy(
            Signal(baseline(W * 200), fs=1.0, kind=SignalKind.REAL), window=W, step=W
        )
        .value()
        .samples
    )
    # test: a fan-out spike embedded in baseline.
    test_codes = np.concatenate([baseline(240), np.arange(W, dtype=np.float64), baseline(240)])
    raw = test_codes.tobytes()
    raw_src = source(raw, evidence=True)
    sig = decode_float64_stream(raw_src, fs=1.0, min_samples=21)
    feat = windowed_entropy(sig, window=W, step=W)
    root = conformal_detect(feat, calibration=cal, alpha=0.02, tail="upper")
    r = root.value()

    decode_claims, _ = decode_guarantee_posture(sig)
    conf_claims, conf_monitors = conformal_guarantee_posture(root, exchangeability=TRUE)
    verdict = assemble_verdict(
        root,
        technique="T1087",  # Account Discovery — enumeration / fan-out
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=r["far_bound"])},
        # decode (demotes) + entropy feature (WELL_FORMED) + conformal detector (BOUNDED, stands)
        claims={**decode_claims, feat.id: Tier.WELL_FORMED, **conf_claims},
        monitors=conf_monitors,
        attestations={raw_src.id: _live_attestation(raw)},
    )
    return root, r, verdict


def test_entropy_conformal_fires_on_the_spike_with_a_distribution_free_bound():
    _, r, _ = _entropy_conformal_verdict()
    assert r["indices"].tolist() == [15]
    assert 0.0 < r["far_bound"] <= r["alpha"]  # the realized finite-sample FAR guarantee


def test_entropy_conformal_verdict_conforms_and_claims_bounded_validly():
    """The third producer: a different TEST (conformal) projects into the same PINNED schema, and
    its bounded claim STANDS (exchangeability confirmed → not demoted) — distribution-free, no
    model to mismatch, unlike CA-CFAR's alpha on a bounded statistic. The detector node claims
    BOUNDED; the end-to-end tier is still WELL_FORMED, capped by the unverified entropy feature +
    decode (a valid-bounded *test* does not un-cap the chain — only verifying the feature/decode
    would)."""
    _, _, verdict = _entropy_conformal_verdict()
    jsonschema.validate(verdict.to_contract(), json.loads(_SCHEMA_PATH.read_text()))
    assert verdict.guarantee.claimed == Tier.BOUNDED   # conformal's distribution-free claim
    assert verdict.guarantee.demotion is None          # it STOOD (exchangeability confirmed)
    assert verdict.guarantee.tier == Tier.WELL_FORMED  # end-to-end: still capped by feature + decode
    assert verdict.decision == TRUE and verdict.score > 0.0


# ── fourth producer: KL × conformal (a two-distribution feature; the binning decision) ──
#
# KL is the first feature that can't dodge the binning decision (entropy histograms each window
# by itself; KL needs window P and baseline Q over an *aligned* alphabet). windowed_kl fixes the
# alphabet to [0, K) from the baseline length, one bin per symbol, Lidstone smoothing. This
# producer wires KL × conformal — a distributional *break* (mass shifting onto symbols rare in
# the baseline), not a fan-out spike — and confirms a structurally different feature (two
# distributions, a `used` baseline edge) still emits the canonical verdict through the same path.


def _kl_conformal_verdict():
    rng = np.random.default_rng(13)
    W, K = 16, 8

    def normal(n):
        x = np.zeros(n)
        flip = rng.random(n) < 0.1
        x[flip] = rng.integers(1, 3, size=flip.sum())
        return x.astype(np.float64)

    # baseline Q: the normal symbol profile (symbol 0 dominant); calibration: KL of a normal stream.
    baseline_counts = np.bincount(normal(W * 400).astype(int), minlength=K).astype(np.float64)
    cal = (
        windowed_kl(
            Signal(normal(W * 200), fs=1.0, kind=SignalKind.REAL),
            baseline=baseline_counts, window=W, step=W,
        ).value().samples
    )
    # test: a distributional break — a window dominated by symbols the baseline barely saw.
    break_win = rng.integers(5, 8, size=W).astype(np.float64)
    test_codes = np.concatenate([normal(240), break_win, normal(240)])
    raw = test_codes.tobytes()
    raw_src = source(raw, evidence=True)
    sig = decode_float64_stream(raw_src, fs=1.0, min_samples=21)
    feat = windowed_kl(sig, baseline=baseline_counts, window=W, step=W)
    root = conformal_detect(feat, calibration=cal, alpha=0.02, tail="upper")
    r = root.value()

    decode_claims, _ = decode_guarantee_posture(sig)
    conf_claims, conf_monitors = conformal_guarantee_posture(root, exchangeability=TRUE)
    verdict = assemble_verdict(
        root,
        technique="T1071",  # Application-layer C2 — a traffic-distribution break
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=r["far_bound"])},
        claims={**decode_claims, feat.id: Tier.WELL_FORMED, **conf_claims},
        monitors=conf_monitors,
        attestations={raw_src.id: _live_attestation(raw)},
    )
    return r, verdict


def test_kl_conformal_is_a_fourth_producer_and_conforms():
    """A structurally different feature (KL, two-distribution, baseline as a used edge) emits the
    same canonical DetectionVerdict: the distributional break fires under conformal, and the
    verdict validates against the PINNED schema with a standing BOUNDED claim."""
    r, verdict = _kl_conformal_verdict()
    assert r["indices"].tolist() == [15]  # the break window is the single detection
    jsonschema.validate(verdict.to_contract(), json.loads(_SCHEMA_PATH.read_text()))
    assert verdict.guarantee.claimed == Tier.BOUNDED and verdict.guarantee.demotion is None
    assert verdict.guarantee.tier == Tier.WELL_FORMED  # capped by the unverified KL feature + decode
    assert verdict.decision == TRUE and verdict.score > 0.0


# ── fifth producer: MI × conformal (a RELATIONAL feature + the permutation null) ──
#
# entropy and KL are univariate (one stream's spread / drift). MI is the first *relational*
# feature — dependence between *two* streams — so it's the coordination cell (lateral movement,
# synchronized C2). Two things distinguish it:
#   1. it's bivariate: windowed_mi takes a second stream as a `used` edge. forge-core stays
#      agnostic — *which* pairs to compute is a knowledge-layer (D3FEND/ATT&CK/OCSF) scoping
#      decision, not the primitive's.
#   2. MI's plug-in estimate is upward-biased, so it is NOT thresholded on its raw value;
#      detection is against a PERMUTATION NULL (mi_shuffle_null) that carries the same bias and
#      cancels it. The shuffle null is exchangeable *by construction*, so conformal's
#      exchangeability precondition stands on firmer ground here than for a collected calibration.


def _mi_conformal_verdict():
    rng = np.random.default_rng(3)
    W, N = 16, 240 + 16 + 240
    x = rng.integers(0, 4, size=N).astype(np.float64)
    y = rng.integers(0, 4, size=N).astype(np.float64)  # independent of x...
    y[240 : 240 + W] = x[240 : 240 + W]  # ...except one window where Y tracks X (coordination)

    raw = x.tobytes()
    raw_src = source(raw, evidence=True)
    sig_x = decode_float64_stream(raw_src, fs=1.0, min_samples=21)
    feat = windowed_mi(
        sig_x, other=Signal(y, fs=1.0, kind=SignalKind.REAL), window=W, step=W
    )
    # the conformal calibration is the permutation null (MI under independence), not a stream.
    null = mi_shuffle_null(x, y, window=W, step=W, n_perm=200, seed=7)
    root = conformal_detect(feat, calibration=null, alpha=0.005, tail="upper")
    r = root.value()

    decode_claims, _ = decode_guarantee_posture(sig_x)
    conf_claims, conf_monitors = conformal_guarantee_posture(root, exchangeability=TRUE)
    verdict = assemble_verdict(
        root,
        technique="T1021",  # Remote Services — lateral movement / coordination
        confidence_evidence={root.id: Confidence.from_detector(True, pd=_PD, pfa=r["far_bound"])},
        claims={**decode_claims, feat.id: Tier.WELL_FORMED, **conf_claims},
        monitors=conf_monitors,
        attestations={raw_src.id: _live_attestation(raw)},
    )
    return r, verdict


def test_mi_conformal_is_a_fifth_producer_and_conforms():
    """The relational feature: MI between two streams, detected against its permutation null,
    emits the same canonical verdict. The coordinated window fires; the verdict validates against
    the PINNED schema with a standing BOUNDED claim (permutation null ⇒ exchangeable by
    construction)."""
    r, verdict = _mi_conformal_verdict()
    assert r["indices"].tolist() == [15]  # the coordinated window is the single detection
    jsonschema.validate(verdict.to_contract(), json.loads(_SCHEMA_PATH.read_text()))
    assert verdict.guarantee.claimed == Tier.BOUNDED and verdict.guarantee.demotion is None
    assert verdict.guarantee.tier == Tier.WELL_FORMED  # capped by the unverified MI feature + decode
    assert verdict.decision == TRUE and verdict.score > 0.0
