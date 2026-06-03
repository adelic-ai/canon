"""CloudTrail fan-out — the third binding, a *new telemetry domain* for the SAME detector.

The fan-out family (``entity → distribution over values``) was validated twice on Windows Kerberos
(:mod:`detection.fanout`). This module runs the *same* bucket/entropy/conformal machinery over AWS
CloudTrail (BOTS v3), changing **only the loader** — which is the claim the third binding is meant to
test: is the fan-out detector corpus-agnostic, or was it Kerberos-shaped? It is corpus-agnostic; only
:func:`load_cloudtrail_events` is new.

Two findings the move to a third corpus surfaced (both tested in ``test_cloudtrail.py``), and they are
the reason this slice is worth more than a fourth green check:

1. **The fan-out axis is domain-specific.** In the cloud-API domain the high-entropy fan-out signal is
   over **awsRegion**, not over the API name. BOTS v3's cryptojacking (``web_admin`` from
   ``139.198.18.205``, 576 ``RunInstances`` across *all 15 AWS regions* — ATT&CK **T1496 Resource
   Hijacking**, on a **T1078.004** compromised cloud credential) shows as a near-maximal region
   entropy (≈ log2(15) = 3.9 bits) that cleanly separates it from every other identity (≤ 1.2 bits).
   Over the *API name* the attacker is the opposite — *low* entropy (mode-collapsed on RunInstances)
   while normal admins are high-entropy — so an API-name fan-out would invert and flag the innocents.
   Choosing the right fan-out axis per domain is a binding decision, not a detector property.

2. **Conformal needs a population; a burst does not supply one.** The whole CloudTrail attack is a
   ~38-minute window (1204 events, ~11 identities). Bucketing by ``(identity, hour)`` yields ~11
   cells, so the conformal floor ``1/(n+1) ≈ 0.08`` sits far above any useful ``alpha`` — the standing
   conformal sweep, at the *same* ``alpha=1e-3`` that works on 30-day Kerberos, **does not fire**, even
   though the signal is visually unmistakable. This is the same structural fact as the FDR-over-cells
   finding: the distribution-free guarantee is empty without a population. Correctly, the detector then
   **emits no verdict** — it refuses to assert a detection its calibration can't justify (the canon
   north star: no result asserted that isn't justified). Detection here needs either an external normal
   baseline (a per-identity history / many normal days — *deferred*, not in this single-burst corpus)
   or the trivial ``distinct-region-count > k`` threshold, which encodes the human prior conformal
   lacks and isolates ``web_admin`` exactly. So on this corpus the trivial baseline *beats* conformal —
   the first concrete data point on the long-open "does conformal beat distinct-count?" question.

Reuse: the bindings are ordinary :class:`~detection.fanout.FanoutBinding` objects (same family),
detections are :class:`~detection.fanout.FanoutDetection`, and verdict-emission is the shared
:func:`~detection.fanout.fanout_verdict`. Nothing here is a new abstraction — that is the result.
"""

from __future__ import annotations

import datetime as dt
import json

from detection.fanout import FanoutBinding

_EPOCH = dt.datetime(1970, 1, 1)  # fixed naive reference → deterministic bucketing (matches fanout.py)


def _identity(record: dict) -> str:
    """The acting principal of a CloudTrail record — the ``userIdentity`` is nested, so collapse it to
    a stable name: the IAM ``userName`` if present, else the ARN's trailing segment (the role/user
    name), else the identity ``type`` (e.g. ``AWSService``). Returns ``"-"`` if wholly absent."""
    u = record.get("userIdentity", {}) or {}
    arn = u.get("arn", "")
    return u.get("userName") or (arn.rsplit("/", 1)[-1] if arn else "") or u.get("type") or "-"


def _field(record: dict, field: str) -> str:
    """Project a CloudTrail field. ``userIdentity`` is the one nested field (collapsed by
    :func:`_identity`); everything else (``eventName``, ``awsRegion``, ``sourceIPAddress``, …) is a
    flat top-level key."""
    return _identity(record) if field == "userIdentity" else str(record.get(field, "-"))


def load_cloudtrail_events(
    path: str,
    *,
    entity_field: str = "userIdentity",
    value_field: str = "awsRegion",
) -> "list[tuple[float, str, str]]":
    """Load an AWS CloudTrail export (``{"Records": [...]}``) into ``(seconds, entity, value)`` events
    — the **concrete, inline** telemetry binding for this corpus, the mirror of
    :func:`~detection.fanout.load_kerberos_events`.

    Same output contract as the Kerberos loader, so :func:`~detection.fanout.run_binding` runs the
    *same* fan-out detector over it (pass ``loader=load_cloudtrail_events``). ``eventTime`` is ISO-8601
    UTC (``...Z``); time is seconds since the fixed naive epoch so bin boundaries are reproducible.
    Defaults bind the region-sweep fan-out (entity = acting credential, value = AWS region).
    """
    with open(path) as f:
        records = json.load(f)["Records"]
    out: list[tuple[float, str, str]] = []
    for e in records:
        t = (dt.datetime.strptime(e["eventTime"], "%Y-%m-%dT%H:%M:%SZ") - _EPOCH).total_seconds()
        out.append((t, _field(e, entity_field), _field(e, value_field)))
    return out


#: Acting credential → many AWS regions in an hour. ATT&CK T1496 (Resource Hijacking) on a
#: T1078.004 (Valid Accounts: Cloud) compromised credential — the multi-region EC2 spin-up sweep of
#: cryptojacking. ``alpha`` is the *same* 1e-3 the Kerberos bindings use, deliberately: the finding is
#: that the sweep fails here for lack of population, not for a mis-chosen threshold.
CLOUDTRAIL_REGION_SWEEP = FanoutBinding(
    name="cloudtrail-region-sweep",
    entity_field="userIdentity",
    value_field="awsRegion",
    grain_seconds=3600,
    technique="T1496",
)
