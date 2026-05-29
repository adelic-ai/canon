import pytest

from forge_core.lattice import (
    divisors,
    prime_factors,
    covers,
    hops_back_walk,
    Scale,
)


def test_divisors():
    assert divisors(12) == [1, 2, 3, 4, 6, 12]
    assert divisors(1) == [1]
    assert divisors(7) == [1, 7]


def test_divisors_rejects_nonpositive():
    with pytest.raises(ValueError):
        divisors(0)


def test_prime_factors():
    assert prime_factors(12) == {2, 3}
    assert prime_factors(8) == {2}
    assert prime_factors(1) == set()
    assert prime_factors(13) == {13}


def test_scale_n_windows():
    assert Scale(value=4, n=12).n_windows == 3


def test_covers_single_prime_steps():
    # divisor 6 of 12: up by 2 -> 12, down by 2 -> 3, down by 3 -> 2
    assert covers(6, 12) == [2, 3, 12]
    # divisor 1: only up by each prime
    assert covers(1, 12) == [2, 3]
    # divisor 12 (top): only down
    assert covers(12, 12) == [4, 6]


def test_covers_rejects_nondivisor():
    with pytest.raises(ValueError):
        covers(5, 12)


def test_hops_zero_is_just_start():
    w = hops_back_walk(12, start=6, hops=0)
    assert [s.value for s in w.scales] == [6]
    assert w.hop_of == {6: 0}


def test_hops_back_walk_bfs_order_and_distance():
    w = hops_back_walk(12, start=6, hops=1)
    # hop 0: 6; hop 1: its covers 2,3,12
    assert w.hop_of[6] == 0
    assert w.hop_of[2] == 1
    assert w.hop_of[3] == 1
    assert w.hop_of[12] == 1
    assert set(s.value for s in w.scales) == {6, 2, 3, 12}


def test_hops_back_walk_reaches_all_divisors_with_enough_hops():
    w = hops_back_walk(12, start=12, hops=10)
    assert set(s.value for s in w.scales) == set(divisors(12))


def test_hops_back_walk_rejects_nondivisor_start():
    with pytest.raises(ValueError):
        hops_back_walk(12, start=5, hops=1)


def test_hops_back_walk_rejects_negative_hops():
    with pytest.raises(ValueError):
        hops_back_walk(12, start=1, hops=-1)
