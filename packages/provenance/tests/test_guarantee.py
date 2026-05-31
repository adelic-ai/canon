"""Guarantee-fold tests — "a tier is earned, never asserted", per node over the DAG.

Covers the three §4 mechanisms: weakest-link composition, per-result demotion tied to the
Belnap monitor verdict, and recorded absence. Plus totality and tier-order monotonicity.
"""
from itertools import product

import pytest

from provenance import (
    BOTH,
    FALSE,
    NONE,
    TRUE,
    Demotion,
    Tier,
    derive,
    guarantee,
    source,
    tier_meet,
)
from provenance.tier import ASSUMPTION_BEARING, FLOOR

K = lambda *a, **k: None  # noqa: E731 — kernels never fire; the fold is structural only


def _chain():
    """a -> b(a) -> c(b). Returns (a, b, c)."""
    a = source(1, name="a")
    b = derive("b", K, (a,))
    c = derive("c", K, (b,))
    return a, b, c


# ── the tier order itself ───────────────────────────────────────────────────────────
def test_tier_total_order():
    assert Tier.ABSENT < Tier.WELL_FORMED < Tier.BOUNDED < Tier.MACHINE_CHECKED


def test_tier_labels_match_schema_enum():
    assert [t.label for t in Tier] == ["absent", "well_formed", "bounded", "machine_checked"]


def test_tier_meet_is_weakest_wins():
    assert tier_meet(Tier.MACHINE_CHECKED, Tier.WELL_FORMED) is Tier.WELL_FORMED
    assert tier_meet(Tier.BOUNDED, Tier.BOUNDED) is Tier.BOUNDED


# ── totality + absence ──────────────────────────────────────────────────────────────
def test_certificate_for_every_node():
    a, b, c = _chain()
    certs = guarantee(c, claims={})
    assert {a.id, b.id, c.id} <= set(certs)  # totality


def test_missing_claim_is_recorded_absence():
    a, b, c = _chain()
    certs = guarantee(c, claims={})
    assert certs[c.id].tier is Tier.ABSENT
    assert certs[c.id].absence == ("guarantee_claim",)


def test_present_claim_has_no_absence():
    a, b, c = _chain()
    certs = guarantee(c, claims={a.id: Tier.WELL_FORMED, b.id: Tier.WELL_FORMED, c.id: Tier.WELL_FORMED})
    assert certs[c.id].absence == ()


def test_subject_cid_is_node_id():
    a, b, c = _chain()
    certs = guarantee(c, claims={})
    assert certs[c.id].subject_cid == c.id


# ── weakest link ────────────────────────────────────────────────────────────────────
def test_weakest_link_caps_downstream():
    # c claims machine_checked but b only earns well_formed -> c earns well_formed.
    a, b, c = _chain()
    certs = guarantee(
        c,
        claims={a.id: Tier.WELL_FORMED, b.id: Tier.WELL_FORMED, c.id: Tier.MACHINE_CHECKED},
        monitors={c.id: TRUE},
    )
    assert certs[c.id].claimed is Tier.MACHINE_CHECKED
    assert certs[c.id].tier is Tier.WELL_FORMED  # capped by the weakest input


def test_uniform_strong_chain_holds():
    a, b, c = _chain()
    strong = {a.id: Tier.BOUNDED, b.id: Tier.BOUNDED, c.id: Tier.BOUNDED}
    conf = {a.id: TRUE, b.id: TRUE, c.id: TRUE}
    certs = guarantee(c, claims=strong, monitors=conf)
    assert certs[c.id].tier is Tier.BOUNDED


# ── per-result demotion tied to the Belnap verdict ──────────────────────────────────
def test_assumption_tier_needs_true_verdict_to_stand():
    a = source(1, name="a")
    n = derive("n", K, (a,))
    claims = {a.id: Tier.WELL_FORMED, n.id: Tier.BOUNDED}
    # NONE (no monitor ran) -> demote to floor, record it. "no data != data-says-fine".
    certs = guarantee(n, claims=claims, monitors={n.id: NONE})
    assert certs[n.id].tier is FLOOR
    assert certs[n.id].demotion == Demotion(from_tier=Tier.BOUNDED, reason=certs[n.id].demotion.reason)
    assert "no data" in certs[n.id].demotion.reason


@pytest.mark.parametrize("verdict", [NONE, FALSE, BOTH])
def test_non_true_verdict_demotes(verdict):
    a = source(1, name="a")
    n = derive("n", K, (a,))
    certs = guarantee(
        n,
        claims={a.id: Tier.WELL_FORMED, n.id: Tier.MACHINE_CHECKED},
        monitors={n.id: verdict},
    )
    assert certs[n.id].tier is FLOOR
    assert certs[n.id].demotion is not None
    assert certs[n.id].demotion.from_tier is Tier.MACHINE_CHECKED


def test_true_verdict_keeps_assumption_tier():
    a = source(1, name="a")
    n = derive("n", K, (a,))
    certs = guarantee(
        n,
        claims={a.id: Tier.WELL_FORMED, n.id: Tier.BOUNDED},
        monitors={n.id: TRUE},
    )
    assert certs[n.id].tier is Tier.BOUNDED
    assert certs[n.id].demotion is None


def test_well_formed_needs_no_verdict():
    # A non-assumption tier stands regardless of monitor (nothing to confirm).
    a = source(1, name="a")
    n = derive("n", K, (a,))
    certs = guarantee(n, claims={a.id: Tier.WELL_FORMED, n.id: Tier.WELL_FORMED})
    assert certs[n.id].tier is Tier.WELL_FORMED
    assert certs[n.id].demotion is None


# ── monotonicity in the TIER order (not leq_k — orthogonal axis, by design) ──────────
def test_earned_tier_monotone_in_claim():
    # Raising the root's claim (assumptions confirmed) only raises-or-holds the earned tier.
    a = source(1, name="a")
    n = derive("n", K, (a,))
    prev = Tier.ABSENT
    for claim in (Tier.ABSENT, Tier.WELL_FORMED, Tier.BOUNDED, Tier.MACHINE_CHECKED):
        certs = guarantee(
            n,
            claims={a.id: Tier.MACHINE_CHECKED, n.id: claim},
            monitors={a.id: TRUE, n.id: TRUE},
        )
        earned = certs[n.id].tier
        assert earned >= prev  # monotone non-decreasing
        prev = earned


def test_verdict_none_to_true_only_promotes():
    # Improving the verdict NONE -> TRUE for an assumption tier promotes (never demotes).
    a = source(1, name="a")
    n = derive("n", K, (a,))
    base = {a.id: Tier.BOUNDED, n.id: Tier.BOUNDED}
    none_earned = guarantee(n, claims=base, monitors={a.id: TRUE, n.id: NONE})[n.id].tier
    true_earned = guarantee(n, claims=base, monitors={a.id: TRUE, n.id: TRUE})[n.id].tier
    assert true_earned >= none_earned
    assert none_earned is FLOOR and true_earned is Tier.BOUNDED
