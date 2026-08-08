"""Guarantee tiers — the honest-by-category ladder, as a total order.

Contract: ``contracts/guarantee_certificate.schema.json`` (the ``tier`` enum) and
architecture spine §4. The load-bearing finding §4 encodes: you **cannot** prove "Pfa ≤ α"
(a statement about the input distribution, not a program property), so a result *earns* a
tier from what actually held on its inputs — it is never asserted.

The four tiers form a total order, weakest → strongest:

    ABSENT  <  WELL_FORMED  <  BOUNDED  <  MACHINE_CHECKED

* ``ABSENT`` — the guarantee joint was not present (a recorded absence, never silent).
* ``WELL_FORMED`` — the floor: SHACL + metamorphic tests + contracts.
* ``BOUNDED`` — where the real detection guarantee lives: analytic CFAR/NP Pfa *conditional
  on the noise model* + a distribution-free conformal bound. Assumption-bearing.
* ``MACHINE_CHECKED`` — the deterministic skeleton only (round-off / algebraic identity /
  threshold monotonicity). Assumption-bearing (the assumption the proof was discharged for
  *this* configuration).

This tier order is its own lattice — **orthogonal** to the Belnap knowledge order
(``carrier.py``); §5/§6: graded earned-strength and knowledge-value are two axes, not one
scalar. The guarantee fold is monotone in *this* order, not ``leq_k``.
"""

from __future__ import annotations

from enum import IntEnum


class Tier(IntEnum):
    """A guarantee tier. Integer values encode the total order (higher = stronger)."""

    ABSENT = 0
    WELL_FORMED = 1
    BOUNDED = 2
    MACHINE_CHECKED = 3

    @property
    def label(self) -> str:
        """The contract's string form, e.g. ``"machine_checked"`` (matches the schema enum)."""
        return self.name.lower()


#: Assumption-bearing tiers: ones whose claim depends on a precondition holding on *this*
#: input, so they require a confirming runtime-monitor verdict to stand (see guarantee.py).
ASSUMPTION_BEARING: frozenset[Tier] = frozenset({Tier.BOUNDED, Tier.MACHINE_CHECKED})

#: The well-formed floor an assumption-bearing tier demotes to when unconfirmed.
FLOOR: Tier = Tier.WELL_FORMED


def tier_meet(a: Tier, b: Tier) -> Tier:
    """Weakest-wins meet — the compositional law: a result is only as strong as its
    weakest justification link."""
    return Tier(min(a, b))
