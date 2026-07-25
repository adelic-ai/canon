"""Partial-kill-chain completeness — mechanical tests on known paths.

A hypothesis is an attack-PATH scored by proximity/probability/identities; this
exercises the path-structure half (completeness, reach, frontier, and the internal
gaps that are entailment GAP candidates) on hand-authored paths with known answers.
"""

from detection.completeness import Completeness, chain_completeness

# a 5-stage path toward a crown jewel
PATH = ["initial-access", "execution", "credential-access", "lateral-movement", "crown-jewel-logon"]


def test_full_path_is_complete():
    r = chain_completeness(PATH, PATH)
    assert r.completeness == 1.0 and r.reach == 1.0
    assert r.complete is True
    assert r.frontier is None
    assert r.internal_gaps == () and r.trailing == ()


def test_contiguous_prefix():
    # first two stages seen, in order, no gaps
    r = chain_completeness(PATH, PATH[:2])
    assert r.completeness == 0.4 and r.reach == 0.4
    assert r.complete is False
    assert r.frontier == "credential-access"                 # next forward milestone
    assert r.internal_gaps == ()                             # nothing skipped
    assert r.trailing == ("credential-access", "lateral-movement", "crown-jewel-logon")


def test_gappy_path_surfaces_an_internal_gap():
    # reached lateral-movement (index 3) but credential-access (index 2) was never seen
    r = chain_completeness(PATH, ["initial-access", "execution", "lateral-movement"])
    assert r.completeness == 0.6                             # 3 of 5 observed
    assert r.reach == 0.8                                    # deepest = index 3 → 4/5
    assert r.reach > r.completeness                          # the gap between them IS the internal-gap mass
    assert r.frontier == "crown-jewel-logon"                # the next forward milestone
    assert r.internal_gaps == ("credential-access",)        # entailed-but-missing (must have happened)
    assert r.trailing == ("crown-jewel-logon",)


def test_jewel_touched_but_blind_to_the_lead_up():
    # the loud case: crown-jewel stage observed, nothing before it
    r = chain_completeness(PATH, ["crown-jewel-logon"])
    assert r.complete is True                                # the jewel was reached
    assert r.reach == 1.0
    assert r.completeness == 0.2                             # but we saw only 1 of 5
    assert r.internal_gaps == ("initial-access", "execution", "credential-access", "lateral-movement")
    assert r.trailing == ()


def test_off_path_and_duplicate_observations_are_ignored():
    r = chain_completeness(PATH, ["execution", "execution", "SOME-UNRELATED-STAGE"])
    assert r.completeness == 0.2                             # only 'execution' counts
    assert r.reach == 0.4                                    # execution is index 1 → 2/5
    assert r.assembled == ("execution",)


def test_nothing_observed():
    r = chain_completeness(PATH, [])
    assert r.completeness == 0.0 and r.reach == 0.0
    assert r.frontier == "initial-access"                    # look for the entry first
    assert r.internal_gaps == ()
    assert r.trailing == tuple(PATH)


def test_empty_path():
    r = chain_completeness([], ["anything"])
    assert isinstance(r, Completeness)
    assert r.completeness == 0.0 and r.reach == 0.0 and r.frontier is None


def test_internal_gaps_are_entailment_gap_candidates():
    # a stage after the deepest reached is 'trailing' (not-yet-reached), a stage
    # before it is an 'internal gap' (entailed-but-missing) — the two are disjoint
    r = chain_completeness(PATH, ["initial-access", "lateral-movement"])
    assert set(r.internal_gaps) & set(r.trailing) == set()
    assert "execution" in r.internal_gaps and "credential-access" in r.internal_gaps
    assert r.trailing == ("crown-jewel-logon",)
