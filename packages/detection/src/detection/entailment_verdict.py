"""Unified entailment verdict — the shared output carrier for canon's three
entailment mechanisms.

They are a STACK, not three copies of one thing (see
``web/detection/three_entailments.html``):

    semantic-core/reasoning.py   DESCRIPTION LOGIC (OWL / HermiT) — OPEN-world
                                 SUBSUMPTION: what entails what at the *type* level
                                 (Kerberoasting ⊑ CredentialAccess). Produces the
                                 necessity edges / rules.
    detection/entailment.py      MODEL-CHECKING (M ⊨ φ) — CLOSED-world evaluation of a
                                 rule over the atom-truth artifact: does the data
                                 satisfy the rule.
    detection/entailment_gap.py  ABDUCTIVE GAP — given a necessity (anchor ⊢ expected),
                                 classify the expected's absence against observability.

Three different logics at three altitudes; they are NOT redundant, and merging them
into one function would be a forced abstraction. What unifies them is the OUTPUT: each
answers "does the evidence support the consequent, and with what epistemic status?"
and maps into one carrier:

    CONFIRMED  entailed and holds / observed                    (~ Belnap TRUE)
    REFUTED    contradicted                                      (~ Belnap FALSE)
    GAP        entailed, but its evidence is ABSENT while OBSERVABLE — the
               entailment/observation divergence; abductive-only, and it resolves to
               TRUE in the substrate fold plus a telemetry-gap warrant on the edge
    NONE       no claim — unobservable, or (open-world) not entailed either way  (~ NONE)

The adapters below encode each mechanism's epistemics HONESTLY. The load-bearing
difference: **closed-world** model-checking can REFUTE from absence (a rule that does
not hold is false), but **open-world** DL subsumption CANNOT — a subsumption that is
not entailed is UNKNOWN (NONE), never refuted, absent an explicit disjointness axiom.
That is the whole reason the carrier needs both REFUTED and NONE.
"""

from __future__ import annotations

from provenance import FALSE as _B_FALSE
from provenance import NONE as _B_NONE
from provenance import TRUE as _B_TRUE

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
GAP = "GAP"
NONE = "NONE"

VERDICTS = (CONFIRMED, REFUTED, GAP, NONE)


def from_gap(outcome: str) -> str:
    """A ``detection.entailment_gap`` outcome is already in the carrier
    (CONFIRMED / GAP / NONE) — the GAP mechanism is the *only* source of GAP, so this
    is the identity plus a validity check."""
    if outcome not in (CONFIRMED, GAP, NONE):
        raise ValueError(f"not a gap outcome: {outcome!r}")
    return outcome


def from_model_check(satisfied: bool) -> str:
    """Map a model-checking result (``M ⊨ φ``, closed-world) into the carrier.
    Closed-world: absence IS refutation, so a rule that does not hold is REFUTED."""
    return CONFIRMED if satisfied else REFUTED


def from_subsumption(entailed: bool) -> str:
    """Map a DL subsumption result (open-world) into the carrier. Open-world: a
    subsumption that is NOT entailed is UNKNOWN (NONE), never REFUTED — you cannot
    refute from absence without an explicit disjointness axiom. This asymmetry with
    :func:`from_model_check` is deliberate and is the point of the unification."""
    return CONFIRMED if entailed else NONE


def entailment_to_belnap(verdict: str):
    """Project a carrier verdict onto the ``provenance`` Belnap value for the substrate
    fold. GAP resolves to TRUE (the step is entailed — it happened); the missing-evidence
    fact is not lost, it rides as a telemetry-gap warrant on the edge, not in the truth
    value. The projection is intentionally lossy in exactly that one place."""
    return {CONFIRMED: _B_TRUE, REFUTED: _B_FALSE, GAP: _B_TRUE, NONE: _B_NONE}[verdict]
