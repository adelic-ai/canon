"""Synthetic enterprise telemetry generator — the activity-first test stand.

Built in stages (see ``design`` / the session scope):
- **L1** ``inventory`` — the reusable org model (users, hosts, service accounts, SPN→account map). HERE.
- L2 ``timeline`` — the single activity timeline (benign + causally-labeled attack), the source of truth.
- L3 ``emit`` — projection of each activity into the WinEventLog XML of every log it touches, with shared
  cross-host join keys (round-trips through :mod:`detection.evtx_xml`).

It is a **test stand, not a fidelity oracle**: it validates pipeline/mechanism/baseline/correlation, never
real-world recall. Generated DATA stays in the workspace (``~/data``); this generator CODE is the instrument.
"""

from detection.synth.inventory import (
    Host,
    Inventory,
    ServiceAccount,
    ServiceSpec,
    User,
    build_inventory,
)

__all__ = ["Host", "User", "ServiceAccount", "ServiceSpec", "Inventory", "build_inventory"]
