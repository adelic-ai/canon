"""The ingest boundary — a real decode joint, validity-checked and honest about its tier.

This is the first reusable *ingest joint*: where raw bytes enter the computation DAG and
become a typed :class:`~forge_core.signal.Signal` a detector can fold. Until now the decode
lived as a per-test lambda (``_normalize``) and its schema check as a test helper; this
promotes both to library ops every detector shares, and — the load-bearing part — makes the
decode's guarantee posture *machine-readable* rather than a code comment.

Three things, matching the three roles the ingest boundary plays:

* **validity** (:func:`validate_float64_stream`) — does the raw payload conform to its
  *declared schema*? This is the §3 validity fold pushed down to the source bytes: a float64
  stream's byte length is a multiple of 8 (the dtype width) and holds enough samples for the
  downstream op. A malformed payload returns ``FALSE`` **carrying the deviation** (the
  detection feature), never a silent drop — dropping collapses "couldn't parse" into "didn't
  happen" (the parser-evasion / absence-as-negative trap).
* **value** (:func:`decode_float64_stream`) — the lazy decode op itself: a bit-faithful
  ``np.frombuffer`` reinterpret of the validated bytes into a REAL Signal.
* **guarantee** (:func:`decode_guarantee_posture`) — the honest tier the decode can *earn*.

The guarantee posture is the reason this joint exists rather than staying a lambda. A
decode's *ceiling* is ``MACHINE_CHECKED``: a byte-faithful reinterpret is an **algebraic
identity with zero round-off** (``frombuffer(tobytes(x))`` is bit-identical to ``x``) —
exactly the deterministic-skeleton property §4 reserves for that tier. But an
assumption-bearing tier only *stands* on a confirming monitor; here that monitor is a
discharged machine-checked proof for this decode configuration. Pure Python has no such proof
(§4: machine_checked "is the only thing that genuinely needs the polyglot path"), so the
default is a **recorded absence**: the guarantee fold demotes the decode to ``WELL_FORMED``
and records the :class:`~provenance.Demotion`. The end-to-end cap on a detection
(``well_formed``, never ``bounded``) is therefore *honest* — the substrate telling the truth
about an unproven step — and **liftable by design**: drop in an F\\*/Coq proof later, pass
``proof=TRUE`` on the inputs it covers, and the decode earns its ceiling with no other change.
The cap is not hardcoded; it is the recorded absence of a proof.
"""

from __future__ import annotations

import numpy as np

from provenance import NONE, TRUE, Entity, Four, Tier, Validity, derive_registered, malformed, VALID

from forge_core.signal import Signal, SignalKind

#: The decode's honest guarantee *ceiling* — see the module docstring. A byte-faithful
#: reinterpret is an algebraic identity (zero round-off), so MACHINE_CHECKED is the strongest
#: tier it could earn *given a discharged proof*; absent one it is a recorded absence that
#: demotes to WELL_FORMED.
DECODE_TIER_CEILING: Tier = Tier.MACHINE_CHECKED


def validate_float64_stream(payload: bytes, *, min_samples: int = 1) -> Validity:
    """Does ``payload`` conform to the declared **float64-stream** schema?

    Two structural constraints, each carried as a deviation on failure (the deviation is the
    feature a detector reads, not a discarded flag):

    * byte length is a multiple of 8 — the IEEE-754 double width; a non-multiple is a truncated
      or misaligned stream;
    * it holds at least ``min_samples`` samples — a downstream op's minimum window (e.g.
      CA-CFAR's reference window).

    Returns :data:`~provenance.VALID` when both hold, else a ``FALSE`` :class:`~provenance.Validity`
    whose ``deviation`` says *how* it is malformed. A malformed payload is **never dropped**
    (the §3 validity discipline): "couldn't parse" is a ``FALSE`` carrying evidence, not a
    ``None``-becomes-nothing silence.
    """
    n = len(payload)
    if n % 8 != 0:
        return malformed(
            f"byte length {n} not a multiple of 8 — truncated float64 stream"
        )
    samples = n // 8
    if samples < min_samples:
        return malformed(
            f"{samples} samples < {min_samples} — below the required minimum window"
        )
    return VALID


def decode_float64_stream(
    raw_src: Entity, *, fs: float = 1.0, min_samples: int = 1
) -> Entity:
    """The lazy ingest decode op: validated raw bytes → a REAL :class:`~forge_core.signal.Signal`.

    Records structure only (laziness — the kernel runs on ``.value()``). The kernel re-checks
    the float64-stream schema before decoding and **raises** on a malformed payload rather than
    emit a bogus Signal: a malformed source must be routed through the validity lens (its
    deviation carried as a feature), *not* decoded. Callers run :func:`validate_float64_stream`
    first and decode only the valid branch (see ``forge-core/tests/test_ingest.py``).

    ``fs`` (sampling rate) and ``min_samples`` are recorded as op params, so the decode node's
    content address depends on them — two decodes that disagree on the declared schema are
    distinct nodes.
    """

    def _decode(payload: bytes, *, fs: float, min_samples: int) -> Signal:
        # params arrive as kwargs from the evaluator (they drive the node's content address);
        # re-check the declared schema and refuse to emit a Signal from a malformed payload.
        v = validate_float64_stream(payload, min_samples=min_samples)
        if v.verdict != TRUE:
            raise ValueError(
                f"refusing to decode a payload that fails its declared schema: {v.deviation}"
            )
        arr = np.frombuffer(payload, dtype=np.float64)
        return Signal(arr, fs=fs, kind=SignalKind.REAL)

    return derive_registered(
        "canon.forge_core.decode_float64_stream",
        _decode,
        (raw_src,),
        {"fs": fs, "min_samples": min_samples},
        kind="REAL",
    )


def decode_guarantee_posture(
    decode: Entity, *, proof: Four = NONE
) -> tuple[dict[str, Tier], dict[str, Four]]:
    """The honest ``(claims, monitors)`` contributions for a decode node, for the guarantee fold.

    Returns the decode's *ceiling* claim (:data:`DECODE_TIER_CEILING` = ``MACHINE_CHECKED``)
    and its proof-monitor verdict. The default ``proof=NONE`` is the **recorded absence** of a
    machine-checked proof: the guarantee fold sees an assumption-bearing claim with a
    non-confirming monitor and demotes the decode to ``WELL_FORMED``, recording the
    :class:`~provenance.Demotion` (``from_tier=MACHINE_CHECKED``). So the end-to-end cap is the
    *recorded absence of a proof*, not a hardcoded floor.

    To lift the cap once a proof exists, pass ``proof=TRUE`` for the inputs the proof covers:
    the decode then earns ``MACHINE_CHECKED`` and the weakest-link meet no longer pins the
    detection at ``well_formed``. Nothing else in the wiring changes — the path is already cut.

    Usage::

        claims, monitors = decode_guarantee_posture(decode)
        certs = guarantee(root, claims={**claims, det.id: Tier.BOUNDED}, monitors={**monitors, ...})
    """
    return {decode.id: DECODE_TIER_CEILING}, {decode.id: proof}
