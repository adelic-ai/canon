"""Divisibility lattice and the hops-back walk.

forge-core views a signal at multiple scales. Candidate scales are the divisors
of the sample count, partially ordered by divisibility (the divisibility
lattice). To choose which scales to actually visit, forge-core walks the lattice
by *hops* along covering edges, replacing forge's ratio-bounded ``horizon``
(design decisions #1 no-horizon, #2 hops-back walk; step-0 verdict: FIX).

A covering edge connects two divisors whose ratio is a single prime: d and d*p
(or d and d/p) are adjacent iff p is prime and both divide n. One hop = one
covering edge. The hops-back walk from a start scale is a breadth-first
exploration of the lattice bounded by a hop count — a principled, lattice-native
neighbourhood, not a multiplicative ball.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass


def divisors(n: int) -> list[int]:
    """All positive divisors of n, ascending."""
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    small, large = [], []
    d = 1
    while d * d <= n:
        if n % d == 0:
            small.append(d)
            if d != n // d:
                large.append(n // d)
        d += 1
    return small + large[::-1]


def prime_factors(n: int) -> set[int]:
    """The distinct prime factors of n."""
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    factors: set[int] = set()
    d = 2
    m = n
    while d * d <= m:
        while m % d == 0:
            factors.add(d)
            m //= d
        d += 1
    if m > 1:
        factors.add(m)
    return factors


@dataclass(frozen=True, slots=True)
class Scale:
    """A scale (divisor of the signal length) plus its lattice position."""

    value: int
    n: int

    @property
    def n_windows(self) -> int:
        return self.n // self.value


def covers(d: int, n: int) -> list[int]:
    """Lattice neighbours of divisor ``d`` reached by one covering edge.

    Returns every divisor of n that differs from d by a single prime factor —
    both d*p (one step coarser in window terms) and d//p (one step finer) when
    each remains a divisor of n.
    """
    if n % d != 0:
        raise ValueError(f"{d} is not a divisor of {n}")
    primes = prime_factors(n)
    out: list[int] = []
    for p in primes:
        up = d * p
        if n % up == 0:
            out.append(up)
        if d % p == 0:
            down = d // p
            if down >= 1 and n % down == 0:
                out.append(down)
    return sorted(set(out))


@dataclass(frozen=True, slots=True)
class LatticeWalk:
    """Result of a lattice walk: the scales visited, with the hop at which each
    was first reached, in breadth-first order from ``start``."""

    scales: list[Scale]
    hop_of: dict[int, int]
    start: int
    n: int


def hops_back_walk(n: int, start: int, hops: int) -> LatticeWalk:
    """Walk the divisibility lattice outward from ``start`` by up to ``hops``
    covering edges (breadth-first).

    This is forge-core's replacement for forge's ``horizon_walk``: instead of
    bounding by a multiplicative ratio, it bounds by graph distance on the
    lattice's covering relation. ``hops=0`` yields just ``start``; each
    additional hop adds the divisors one prime-factor away from the current
    frontier.
    """
    divs = set(divisors(n))
    if start not in divs:
        raise ValueError(f"start {start} is not a divisor of {n}")
    if hops < 0:
        raise ValueError(f"hops must be >= 0, got {hops}")

    hop_of: dict[int, int] = {start: 0}
    order: list[int] = [start]
    frontier: deque[int] = deque([start])
    while frontier:
        d = frontier.popleft()
        if hop_of[d] >= hops:
            continue
        for nb in covers(d, n):
            if nb not in hop_of:
                hop_of[nb] = hop_of[d] + 1
                order.append(nb)
                frontier.append(nb)

    scales = [Scale(value=v, n=n) for v in order]
    return LatticeWalk(scales=scales, hop_of=hop_of, start=start, n=n)
