"""The validity fold — does a raw input conform to its declared shape? And what does a failure mean?

Contract: architecture spine §3 (well-formedness) pushed down to the *source payload*, plus the
session finding that input validation is **not a discard gate** — it is evidence about the chain.

Validity answers a question distinct from both neighbours, and a malformed source is what *only*
this fold sees:

* **guarantee tier** — rigor of a *computation*. A source has none (it is tier-transparent).
* **custody** — were the bytes *tampered in transit* (integrity). It returns ``TRUE`` on
  intact-but-malformed bytes; it never inspects content.
* **validity** — does the *content* conform to its declared schema/kind. This catches a
  malformed source — what neither of the others can.

Carrier-valued (:class:`~provenance.carrier.Four`), and it carries the **deviation** (how it is
malformed), not merely that it is — because the deviation is a *detection feature*, the same way a
``NONE`` carries which input was missing.

Two couplings, both load-bearing, both ``≤_k``-monotone:

1. **Validity feeds custody as a soundness signal — but cannot vindicate it.**
   :func:`trustworthiness` ``= kjoin(custody, evidence(validity))`` where a *valid* payload
   contributes ``NONE`` (clean content vindicates nothing — valid-but-tampered is real) and a
   *malformed* payload contributes ``FALSE`` (it contests the chain). So intact digest-custody
   (``TRUE``) + malformed content (``FALSE``) fuse to ``BOTH`` — the soundness alarm: the bytes
   were faithfully delivered yet are bunk, so the corruption is *upstream of where custody can
   see* (compromise or bug — unknown which). Not ``FALSE`` (we have not proven tampering); ``BOTH``
   (two credible signals contradict). Intact custody does not *weaken* a malformed payload's
   signal — it *strengthens* it: the bunk is real as observed, not a transit artifact.

2. **A malformed source is NOT a discard, and NOT ``what = FALSE``.** Dropping malformed input
   turns "couldn't parse" into "nothing happened" — the ``NONE``→``FALSE`` collapse, and a
   parser-evasion vector (malform the payload so the detector never sees the event). The
   malformation is data: to the detection lens the deviation is a *feature*. ``what`` becomes
   ``TRUE`` when the deviation matches the technique's signature (the malformation **is** the
   artifact — e.g. a protocol violation from an exploit), or ``NONE`` when a field the detector
   needed is now unparseable (can't tell). Never a blanket ``FALSE``. This fold does not decide
   which: the corruption-vs-attack call is left to correlation (the temporal fold) and held as
   ``BOTH`` / escalated until evidence breaks the tie.
"""

from __future__ import annotations

from dataclasses import dataclass

from provenance.carrier import BOTH, FALSE, NONE, TRUE, Four, kjoin


@dataclass(frozen=True, slots=True)
class Validity:
    """A source-payload validity verdict plus the deviation that explains a failure.

    ``verdict`` is carrier-valued: ``TRUE`` conforms, ``FALSE`` malformed, ``NONE`` unchecked
    (no validator ran — "no data ≠ data-says-fine"). ``deviation`` records *how* it is malformed
    (which constraint failed), because that is the feature a detector reads — empty when valid or
    unchecked."""

    verdict: Four
    deviation: tuple[str, ...] = ()


#: Conforms to its declared shape.
VALID = Validity(TRUE, ())
#: No validator ran. NONE, never TRUE — absence of a check is not a clean bill of health.
UNCHECKED = Validity(NONE, ())


def malformed(*deviation: str) -> Validity:
    """A ``FALSE`` validity carrying the deviation(s) — the detection feature, not just a flag."""
    return Validity(FALSE, tuple(deviation))


def _as_integrity_evidence(verdict: Four) -> Four:
    """Validity recast as evidence about *chain integrity*.

    Malformed/contradictory content contests the chain (``FALSE``); valid or unchecked content
    vindicates nothing (``NONE``) — clean content cannot clear custody, because valid-but-tampered
    is real. ``≤_k``-monotone (tested), so :func:`trustworthiness` is monotone in validity.
    """
    return FALSE if verdict in (FALSE, BOTH) else NONE


def trustworthiness(custody: Four, validity: Validity) -> Four:
    """End-to-end trust = digest-custody knowledge-joined with the validity soundness signal.

    ``kjoin`` is the knowledge join (componentwise OR on the ``(t, f)`` bits), so:

    * intact custody (``TRUE``) + valid/unchecked content → ``TRUE`` (nothing contests it),
    * intact custody (``TRUE``) + **malformed** content → ``BOTH`` (the soundness alarm:
      faithfully delivered yet bunk → corruption upstream of custody's reach),
    * tampered custody (``FALSE``) → ``FALSE`` regardless (absorbing — proven in-transit tamper),
    * silent custody (``NONE``) + malformed → ``FALSE`` (one negative signal, no positive).

    Monotone in both arguments (``kjoin`` is, and :func:`_as_integrity_evidence` is), so it obeys
    the universal ``≤_k`` invariant.
    """
    return kjoin(custody, _as_integrity_evidence(validity.verdict))
