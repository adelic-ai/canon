"""Rarity detector — flag the rare ACTOR for a sensitive action family.

The complement of the entropy fan-out. Diversity is the right signal for ENUMERATION (broad recon is
suspicious) and the WRONG one for CREDENTIAL-ACCESS / account-manipulation: diverse IAM activity is
exactly what a legitimate admin does, so an entropy fan-out flags the account owner (empirically:
`root` on flaws — see detection/cloudtrail.py). Rarity asks the right question — is this identity a
RARE doer of the sensitive action relative to the population? The established admin/automation owns
most of the manipulation activity (the baseline, not flagged); an identity responsible for only a tiny
SHARE of it that nonetheless performs a privilege grant is the anomaly — e.g. a stolen EC2-instance
role manipulating IAM (the flaws.cloud instance-credential path).

This is canon's first rarity primitive (it had entropy/conformal fan-out, temporal, coordination, and
structural signatures — but no rarity). It carries NO conformal FAR — rarity is a population-share
statistic, not a distribution-free test — so emitted verdicts have calibration=None (honest: no FAR
bound), the same as the structural detectors.
"""

from __future__ import annotations

import json
from collections import Counter

from forge_core import DetectionVerdict

from detection._verdict import emit_detection_verdict
from detection.cloudtrail import MANIPULATION_APIS, _identity


def rare_actors(counts: Counter, *, max_share: float) -> list[tuple[str, int, float]]:
    """Actors responsible for less than ``max_share`` of a family's total events — the rare-doer tail.
    The dominant doers (established admins / automation) are the baseline and are NOT returned.
    Returns ``(actor, count, share)`` sorted by ascending share (rarest first)."""
    total = sum(counts.values()) or 1
    tail = [(who, n, n / total) for who, n in counts.items() if n / total < max_share]
    return sorted(tail, key=lambda t: t[2])


def cloud_account_manipulation_verdicts(path: str, *, max_share: float = 0.05) -> list[DetectionVerdict]:
    """Rarity over the IAM privilege-manipulation family on CloudTrail → ATT&CK T1098 verdicts. Flags
    rare doers of manipulation (not the established admin). ``calibration=None`` — rarity has no
    distribution-free FAR; ``pvalue`` carries the population share as a rough confidence proxy only."""
    with open(path) as f:
        records = json.load(f)["Records"]
    counts: Counter = Counter()
    for e in records:
        if e.get("eventName") in MANIPULATION_APIS:
            counts[_identity(e)] += 1
    return [
        emit_detection_verdict(
            f"cloudtrail-account-manipulation|{who}",
            technique="T1098",
            pvalue=share,                       # rough confidence proxy; NOT a conformal FAR
            params={"identity": who, "manipulation_events": n, "population_share": round(share, 4)},
            calibration=None,                   # rarity is a share statistic, not distribution-free
        )
        for who, n, share in rare_actors(counts, max_share=max_share)
    ]
