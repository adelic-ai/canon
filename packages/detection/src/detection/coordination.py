"""Coordination detection — the third detector FAMILY, and MI's constructive existence-proof.

The fan-out and off-hours families both read **one entity → a distribution**; mutual information reads
**two entity streams → their dependence**. That is a genuinely different binding shape (it pairs
entities), and it is the one the prior families said to wait for before generalizing ``Binding``.

This module is a *constructively validated capability*, not a field-validated detector — a precise and
deliberately limited claim (see the guarantees ledger). It establishes three things and no more:
  1. the implementation works (`windowed_mi` + `mi_shuffle_null` fire on a real dependence);
  2. on a corpus where the coordination is a *consequence of a modelled attack mechanism* (synchronized
     multi-host C2 beaconing), MI recovers exactly the coordinated hosts;
  3. **MI beats the marginals** — on the *same* corpus the per-host marginal detectors (activity rate,
     activity entropy) cannot separate the coordinated hosts from normal ones, because the corpus is
     built so each host is *individually* indistinguishable and only the cross-host coupling is strong.
It does **not** establish operational value on real attacks — the signal is synthetic, ground truth is
ours by construction. The corpus models a *mechanism* (a shared beacon schedule), it does not plant an
MI-shaped blob: that distinction is what keeps (3) from being teaching-to-the-test (the same reason
faker-kerberos's fan-out was real — the entropy was a consequence of the spray, not planted).

Why FDR here and a per-cell alpha in `fanout.py`: the pair sweep is O(n²) candidate pairs against a
*clean permutation null* — the **reduced-multiplicity discovery tier** where Benjamini–Hochberg is the
right control (the fan-out finding's other half: T0 sweeps use alpha; T1 scoped-pair discovery uses FDR).

The pipeline:

    events (time, host)  →  per-(host, window) activity vectors  →  for each host PAIR:
        MI(X,Y) vs its permutation null → p-value  →  FDR across pairs  →  coordinated pairs  →  verdict
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from forge_core import (
    DetectionVerdict,
    fdr_control,
    mi_shuffle_null,
    mutual_information,
    shannon_entropy,
)

from detection._verdict import emit_detection_verdict


# ── the corpus: a modelled mechanism (synchronized beaconing), not a planted signature ────────────


def synthesize_coordination_events(
    *,
    n_normal: int,
    n_compromised: int,
    n_windows: int,
    rate: float,
    beacon_rate: float,
    grain_seconds: float,
    seed: int,
) -> "tuple[list[tuple[float, str]], set[str]]":
    """Generate ``(time, host)`` events for a botnet whose compromised hosts share a beacon schedule.

    The mechanism, not the signature: there is a single latent **beacon** ``B_w ~ Bernoulli(beacon_rate)``
    per window, *shared by every compromised host*. A compromised host is active in window ``w`` iff the
    beacon fired **or** its own background did (``background ~ Bernoulli(r)``); a normal host is active
    iff ``Bernoulli(rate)``. The background rate is set to ``r = (rate - beacon_rate)/(1 - beacon_rate)``
    so that **every host — normal or compromised — has the identical marginal activity rate ``rate``.**
    Each host is therefore *individually* a normal host; only the *shared* beacon couples the compromised
    ones. That is the hard case: marginals are blind by construction, the coupling alone carries the
    signal. One event is emitted per active window (jittered within it), so per-host event counts match
    too. Returns the events (sorted by time) and the ground-truth set of compromised host ids.

    ATT&CK: the modelled mechanism is C2 beaconing (T1071 / T1102) — coordinated callbacks on a schedule.
    """
    if not 0.0 <= beacon_rate < rate <= 1.0:
        raise ValueError(f"need 0 <= beacon_rate < rate <= 1; got beacon_rate={beacon_rate}, rate={rate}")
    rng = np.random.default_rng(seed)
    beacon = rng.random(n_windows) < beacon_rate  # the shared schedule B_w
    r = (rate - beacon_rate) / (1.0 - beacon_rate)  # background → marginal activity == rate for all hosts

    active: dict[str, np.ndarray] = {}
    for i in range(n_normal):
        active[f"host-n{i:02d}"] = rng.random(n_windows) < rate
    compromised: set[str] = set()
    for i in range(n_compromised):
        h = f"host-c{i:02d}"
        active[h] = beacon | (rng.random(n_windows) < r)  # shared beacon OR own background
        compromised.add(h)

    events: list[tuple[float, str]] = []
    for h, vec in active.items():
        for w in np.flatnonzero(vec):
            events.append((float(w * grain_seconds + rng.random() * grain_seconds), h))
    events.sort()
    return events, compromised


# ── telemetry → spine: events into aligned per-host activity vectors ───────────────────────────────


def host_activity_vectors(
    events: "list[tuple[float, str]]", *, grain_seconds: float
) -> dict[str, np.ndarray]:
    """Bucket ``(time, host)`` events into one **binary activity vector per host**, aligned to a common
    window axis (``1`` = the host had ≥1 event in that window). The materialized grain step, as in
    ``fanout.bucket_fanout`` — the window axis is the load-bearing choice. Vectors share a length
    (``max window + 1``) so any pair is directly comparable by :func:`~forge_core.mutual_information`."""
    if grain_seconds <= 0:
        raise ValueError(f"grain_seconds must be > 0, got {grain_seconds}")
    if not events:
        raise ValueError("no events")
    n_windows = max(int(t // grain_seconds) for t, _ in events) + 1
    hosts = sorted({h for _, h in events})
    vec = {h: np.zeros(n_windows, dtype=np.int64) for h in hosts}
    for t, h in events:
        vec[h][int(t // grain_seconds)] = 1  # binary: active-in-window (1 event/active-window by construction)
    return vec


@dataclass(frozen=True, slots=True)
class CoordinationDetection:
    """A detected coordinated host *pair* — the unit the coordination family emits (note: a *pair*, not a
    single entity — the new binding shape). ``mi`` is the observed mutual information (bits) between the
    two hosts' activity vectors; ``pvalue`` its permutation-null p-value (the bias-cancelled rarity)."""

    host_a: str
    host_b: str
    mi: float
    pvalue: float


@dataclass(frozen=True, slots=True)
class CoordinationBinding:
    """A named coordination binding — the *two-stream* binding shape (cf. the single-stream
    ``FanoutBinding``). It pairs the entity against itself (host × host here) and scopes the O(n²) sweep;
    a knowledge layer would later scope *which* pairs are worth testing. ``q`` is the FDR level (this is
    the T1 discovery tier), ``n_perm`` the permutation-null size, ``technique`` the ATT&CK id evidenced."""

    name: str
    grain_seconds: float
    technique: str
    q: float = 0.05
    n_perm: int = 199


#: Synchronized multi-host C2 beaconing — coordinated callbacks on a shared schedule. ATT&CK T1071.
BEACON_COORDINATION = CoordinationBinding(
    name="beacon-coordination",
    grain_seconds=600,
    technique="T1071",
)


def detect_coordination(
    events: "list[tuple[float, str]]",
    *,
    grain_seconds: float,
    q: float = 0.05,
    n_perm: int = 199,
    seed: int,
) -> dict:
    """Detect coordinated host pairs: per pair, MI of the two activity vectors vs its permutation null
    → p-value → **FDR (Benjamini–Hochberg) across all pairs** at level ``q``. Returns a dict with
    ``detected`` (the rejected :class:`CoordinationDetection` pairs), ``pairs`` (all scored pairs),
    ``vectors`` (per-host activity, for the marginal co-run), ``n_pairs``, ``q``.

    The permutation null (:func:`~forge_core.mi_shuffle_null`) carries MI's finite-sample upward bias,
    so the p-value is bias-cancelled (the raw MI is never thresholded). FDR — not a per-cell alpha — is
    correct here precisely because this is a *scoped-pair sweep against a clean null*."""
    vectors = host_activity_vectors(events, grain_seconds=grain_seconds)
    hosts = sorted(vectors)
    pairs = [(hosts[i], hosts[j]) for i in range(len(hosts)) for j in range(i + 1, len(hosts))]
    if not pairs:
        raise ValueError("need >= 2 hosts to test coordination")

    scored: list[CoordinationDetection] = []
    for k, (ha, hb) in enumerate(pairs):
        a, b = vectors[ha], vectors[hb]
        obs = mutual_information(a, b)
        null = mi_shuffle_null(a, b, window=len(a), step=1, n_perm=n_perm, seed=seed + k)
        pvalue = float((1 + np.count_nonzero(null >= obs)) / (n_perm + 1))
        scored.append(CoordinationDetection(host_a=ha, host_b=hb, mi=obs, pvalue=pvalue))

    rejected = fdr_control(np.array([d.pvalue for d in scored]), q=q)["rejected"]
    return {
        "detected": [d for d, r in zip(scored, rejected) if r],
        "pairs": scored,
        "vectors": vectors,
        "n_pairs": len(pairs),
        "q": q,
    }


# ── the marginal co-run: the test that the marginals are blind ────────────────────────────────────


def host_marginal_features(vectors: dict[str, np.ndarray]) -> dict[str, tuple[float, float]]:
    """Per host, the two single-stream marginal features a fan-out/entropy detector would see: the
    **activity rate** (fraction of windows active) and the **activity entropy** (bits of the
    active/inactive distribution). By construction these are statistically identical for coordinated and
    normal hosts — the data the marginal detectors are blind to. Returns ``host -> (rate, entropy)``."""
    out: dict[str, tuple[float, float]] = {}
    for h, v in vectors.items():
        n_active = int(v.sum())
        _, counts = np.unique(v, return_counts=True)
        out[h] = (n_active / v.size, shannon_entropy(counts))
    return out


def coordination_verdict(detection: CoordinationDetection, binding: CoordinationBinding) -> DetectionVerdict:
    """Emit the canonical :class:`~forge_core.DetectionVerdict` for one coordinated pair. ``who`` grounds
    the *pair* (both hosts); custody is honestly ``NONE`` (synthetic, unattested corpus). Reuses the
    shared :func:`~detection._verdict.emit_detection_verdict` — the third family confirms that helper
    generalizes (shared *behavior*), even though the binding *shape* is new (shared *ontology* does not)."""
    return emit_detection_verdict(
        f"{binding.name}|{detection.host_a}|{detection.host_b}",
        technique=binding.technique,
        pvalue=detection.pvalue,
        params={
            "host_a": detection.host_a,
            "host_b": detection.host_b,
            "mi_bits": detection.mi,
            "technique": binding.technique,
        },
    )


def coordination_verdicts(result: dict, binding: CoordinationBinding) -> "list[DetectionVerdict]":
    """One verdict per detected coordinated pair in a :func:`detect_coordination` result."""
    return [coordination_verdict(d, binding) for d in result["detected"]]
