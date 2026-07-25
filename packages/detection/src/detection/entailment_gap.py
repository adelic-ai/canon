"""Entailment GAP classification — a necessary-but-missing step becomes evidence.

An ANCHOR observation ENTAILS an EXPECTED one: a hard necessity where the anchor
cannot have occurred without the expected also occurring (e.g. a comsvcs MiniDump
spawn ENTAILS a VM_READ to lsass — you cannot dump credentials without reading
lsass memory). Replaying the anchor, the expected motif's presence/absence
classifies three ways *against observability*:

    CONFIRMED  expected present                                  -> grounds TRUE
    GAP        expected ABSENT, but its channel IS collected      -> it happened
               (entailed from the anchor), yet its record is         (telemetry gap /
               missing                                               anti-forensic /
                                                                     evasion) -- "it
                                                                     didn't happen" is
                                                                     RULED OUT
    NONE       expected absent, and its channel is NOT collected  -> unobservable, no claim

The load-bearing move: because the anchor ENTAILS the expected, the GAP case rules
out "it didn't happen" — the absence is promoted from silence to evidence, and the
cause narrows from {organic / collection-fail / evasion} to {collection-fail /
evasion}. NONE is the discipline that *refuses* a claim when the channel is not
even collected — the system does not manufacture a verdict where it cannot see.

This is the executable core of ``experiments/entailment_test.py`` (the comsvcs ⊢
lsass demo), lifted out of that experiments script into tested ``src`` and made
domain-general: a motif is a plain predicate + join + channel over events, so it
carries no dependency on the experiments-only subgraph modules. See
``web/detection/kerberos_state_table.html`` for the same GAP mechanism applied to
Kerberos ticket forgeries (a presented ticket with no entailed issuance).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

# The three-way outcome (an enumerated verdict, sibling to the Belnap carrier's
# values — kept as module constants; NOT re-exported bare, so as not to shadow
# provenance.NONE at the package top level).
CONFIRMED = "CONFIRMED"
GAP = "GAP"
NONE = "NONE"


@dataclass(frozen=True)
class EntailedMotif:
    """A minimal motif over events: which events *are* the motif (``pred``), how
    they join to an anchor (``join``), and which events sit on the motif's
    observation *channel* (``channel`` — used to decide collected-ness).

    For the expected motif, ``pred`` is the full match (channel + value predicate)
    while ``channel`` is the broader "is this event even on that channel" test —
    e.g. ``pred`` = "EID 10 to lsass" but ``channel`` = "any EID 10". That gap
    between them is exactly what separates GAP (channel collected, record missing)
    from NONE (channel not collected at all)."""
    pred: Callable[[dict], bool]
    join: Callable[[dict], Any]
    channel: Callable[[dict], bool] = lambda _e: True


@dataclass(frozen=True)
class Entailment:
    """``anchor present  ⊢  expect`` (with a rationale) — the forward-progression
    necessity edge the GAP classification is read against."""
    rationale: str
    anchor: EntailedMotif
    expected: EntailedMotif


def classify(*, expected_present: bool, channel_collected: bool) -> str:
    """The whole three-way rule, in one pure function. Present → CONFIRMED;
    absent-but-observable → GAP; absent-and-unobservable → NONE."""
    if expected_present:
        return CONFIRMED
    return GAP if channel_collected else NONE


def classify_entailment(ent: Entailment, events: list[dict]) -> dict:
    """For each anchor instance (grouped by join value), look for the entailed
    motif joined at the same node and classify it against observability.

    Returns ``{rationale, channel_collected, findings, counts}`` where each finding
    is ``{join, outcome}`` and ``counts`` tallies CONFIRMED / GAP / NONE."""
    # Is the expected motif's channel collected at all in this corpus? (One global
    # fact — the difference between "we didn't record it" and "we weren't watching".)
    channel_collected = any(ent.expected.channel(e) for e in events)

    # Expected-motif hits, grouped by join value.
    expected_by_join: dict[Any, list[dict]] = defaultdict(list)
    for e in events:
        if ent.expected.pred(e):
            expected_by_join[ent.expected.join(e)].append(e)

    # Anchor instances, grouped by join value.
    anchors_by_join: dict[Any, list[dict]] = defaultdict(list)
    for e in events:
        if ent.anchor.pred(e):
            anchors_by_join[ent.anchor.join(e)].append(e)

    findings: list[dict] = []
    counts = {CONFIRMED: 0, GAP: 0, NONE: 0}
    for jv in anchors_by_join:
        present = bool(expected_by_join.get(jv))
        outcome = classify(expected_present=present, channel_collected=channel_collected)
        counts[outcome] += 1
        findings.append({"join": jv, "outcome": outcome})

    return {"rationale": ent.rationale, "channel_collected": channel_collected,
            "findings": findings, "counts": counts}
