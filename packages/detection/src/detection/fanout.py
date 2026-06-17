"""Fan-out detection — the first telemetry→spine slice (Kerberos password-spray).

A *fan-out* is one entity touching unusually many distinct values in a window. The same detector,
under two different **bindings**, catches two different attack classes in the ``faker-kerberos``
corpus — which is the repeated structure the binding abstraction is meant to emerge from:

    password spray   entity = Client_Address (source IP)   value = Account_Name
    service-ticket   entity = Account_Name                 value = Service_Name

The first finds a source IP hitting many accounts (password spray). The second finds an account
requesting many distinct service tickets — which catches **Kerberoasting *and* pass-the-ticket**
together, because both are "one account, many service tickets": the detector keys on the fan-out
signature, not the technique label. The detection is the cyber instantiation of the
``entropy × conformal`` producer proven in forge-core, here fed by **real, labeled** telemetry.

The pipeline, with the layer boundary kept sharp:

    events  →  [bucket by (entity, time-bin)]  →  shannon_entropy per cell  →  conformal p-value
            →  FDR across all cells  →  detected cells

* **This layer** owns the *semantic* bucketing: partition events by entity, bin by a chosen
  **grain** (time-bin width), project the value field. That bucketing is **materialized** — a real
  step that produces a concrete artifact — so the grain is *load-bearing*, not decorative: a
  different grain yields different cells (the guard against the recurring ``c_bin → 1`` collapse,
  tested in ``test_fanout.py``).
* **forge-core** owns the math: :func:`~forge_core.shannon_entropy` (the entropy primitive — note
  this layer's windowing is a *time-bin*, distinct from the DSP ``windowed_entropy`` op whose window
  is a sample count; both reuse the same primitive), :func:`~forge_core.conformal_pvalues`,
  :func:`~forge_core.fdr_control`.

Scope of this first slice: the binding is **concrete and inline** (no ``StreamBinding`` abstraction
— that is meant to *emerge* once a second slice forces its shape). It detects cells and validates
them against ground truth; wrapping each detection in a full ``DetectionVerdict`` is the immediate
next increment (the verdict path is already proven five times over in forge-core).
"""

from __future__ import annotations

import csv
import datetime as dt
from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from forge_core import (
    Calibration,
    DetectionVerdict,
    conformal_pvalues,
    exchangeability_monitor,
    shannon_entropy,
)
from provenance import FALSE, NONE, TRUE, Four

from detection._verdict import emit_detection_verdict

_EPOCH = dt.datetime(1970, 1, 1)  # fixed naive reference → deterministic bucketing across machines


def load_kerberos_events(
    path: str,
    *,
    entity_field: str = "Client_Address",
    value_field: str = "Account_Name",
) -> "list[tuple[float, str, str]]":
    """Load a Kerberos CSV (``faker-kerberos`` Splunk-style schema) into ``(seconds, entity, value)``
    events — the **concrete, inline** telemetry binding for this corpus.

    This is deliberately *not* a generic ``StreamBinding``: the field names are this schema's, and
    the abstraction is meant to *emerge* once a second slice (e.g. MI coordination) forces its shape.
    Defaults bind the password-spray fan-out (entity = source IP, value = account); pass
    ``entity_field="Account_Name", value_field="Service_Name"`` for the Kerberoasting fan-out. IPv4-
    mapped-IPv6 prefixes (``::ffff:``) are stripped. Time is seconds since a fixed naive epoch
    (timezone-independent, so bin boundaries are reproducible).
    """
    out: list[tuple[float, str, str]] = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            t = (dt.datetime.strptime(row["_time"], "%Y-%m-%d %H:%M:%S.%f") - _EPOCH).total_seconds()
            entity = row[entity_field].replace("::ffff:", "")
            out.append((t, entity, row[value_field]))
    return out


@dataclass(frozen=True, slots=True)
class FanoutCell:
    """One (entity, time-bin) cell and its fan-out entropy — the unit a fan-out detector scores.

    ``entity`` is the partition key (e.g. a source IP), ``bin`` the integer time-bin index at the
    chosen grain, ``entropy`` the Shannon entropy (bits) of the distinct values touched in the cell.
    ``bin_start`` is the cell's start time in epoch seconds (``bin * grain_seconds``). ``distinct`` is
    the count of distinct values — the *independent* fan-out measure entropy is cross-checked against
    (carried for free; it's the cardinality the entropy is the spread of)."""

    entity: str
    bin: int
    entropy: float
    bin_start: float
    distinct: int


@dataclass(frozen=True, slots=True)
class FanoutDetection:
    """A detected fan-out: the :class:`FanoutCell` plus its conformal ``pvalue`` (the per-cell
    rarity against the population — the false-alarm rate of *this* detection)."""

    cell: FanoutCell
    pvalue: float


def bucket_fanout(
    events: "list[tuple[float, str, str]]", *, grain_seconds: float
) -> dict[tuple[str, int], list[str]]:
    """The **materialized grain step**: group ``(timestamp, entity, value)`` events into
    ``(entity, time-bin)`` cells, each holding the values touched in that cell.

    ``grain_seconds`` is the time-bin width — *the* design choice. It is load-bearing here by
    construction: changing it changes the cell partition (and therefore every downstream entropy),
    which is exactly the property the c_bin-collapse guard checks. ``bin = floor(t / grain)``.
    """
    if grain_seconds <= 0:
        raise ValueError(f"grain_seconds must be > 0, got {grain_seconds}")
    cells: dict[tuple[str, int], list[str]] = defaultdict(list)
    for ts, entity, value in events:
        cells[(entity, int(ts // grain_seconds))].append(value)
    return cells


def fanout_entropy(
    events: "list[tuple[float, str, str]]", *, grain_seconds: float
) -> list[FanoutCell]:
    """Per ``(entity, time-bin)`` cell, the fan-out statistic = Shannon entropy of the distinct
    values touched. Reuses forge-core's :func:`~forge_core.shannon_entropy`; the time-bin bucketing
    is this layer's. Returns one :class:`FanoutCell` per non-empty cell."""
    cells = bucket_fanout(events, grain_seconds=grain_seconds)
    out: list[FanoutCell] = []
    for (entity, b), values in cells.items():
        _, counts = np.unique(np.asarray(values), return_counts=True)
        out.append(
            FanoutCell(
                entity=entity,
                bin=b,
                entropy=shannon_entropy(counts),
                bin_start=b * grain_seconds,
                distinct=len(counts),
            )
        )
    return out


def detect_fanout(
    events: "list[tuple[float, str, str]]",
    *,
    grain_seconds: float,
    alpha: float = 1e-3,
) -> dict:
    """Detect fan-out cells: entropy per cell → conformal p-value against the population baseline
    → flag cells with ``p <= alpha``. This is a **T0 standing sweep** (cheap, every cell).

    The conformal calibration is the cell population itself (the bulk of cells are low-entropy
    normal; fan-outs are rare upper-tail outliers): ``p = (1 + #{e' >= e}) / (n+1)``. Mild
    contamination by the rare fan-outs only makes the test *conservative*.

    **Why a per-cell alpha and not FDR here (a finding from the first real slice).** FDR over
    *every* cell rejects nothing: the discrete conformal floor ``1/(n+1)`` is ``~1/q`` times the
    Benjamini–Hochberg threshold ``q/m`` at this multiplicity (m ~ 10⁴ cells), so even the most
    extreme cell can't pass. FDR is the right control for the *reduced-multiplicity* discovery path
    (scoped candidate pairs with a clean permutation null), **not** a gross-outlier sweep over all
    cells — tiered dispatch: T0 sweeps with a per-cell ``alpha``; FDR enters at T1 after scoping.
    (Demonstrated in ``test_fanout.py::test_fdr_over_all_cells_is_too_stringent_a_t0_sweep_uses_alpha``.)

    Returns a dict: ``cells`` (all :class:`FanoutCell`), ``pvalues``, ``detected`` (``p <= alpha``),
    ``alpha``, ``grain_seconds``.
    """
    cells = fanout_entropy(events, grain_seconds=grain_seconds)
    if not cells:
        raise ValueError("no cells: empty events")
    ent = np.array([c.entropy for c in cells], dtype=np.float64)
    pvalues = conformal_pvalues(ent, ent, tail="upper")  # each cell vs the population
    detected = [
        FanoutDetection(cell=cells[i], pvalue=float(pvalues[i]))
        for i in np.flatnonzero(pvalues <= alpha)
    ]
    return {
        "cells": cells,
        "pvalues": pvalues,
        "detected": detected,
        "alpha": alpha,
        "grain_seconds": grain_seconds,
    }


@dataclass(frozen=True, slots=True)
class FanoutBinding:
    """A named fan-out detection binding — *the repeated structure made data*.

    The two real Kerberos detections differ only in this object: which field is the ``entity``,
    which is the ``value`` it fans out over, the time ``grain``, the sweep ``alpha``, and the ATT&CK
    ``technique`` the fan-out evidences. Extracted only *after* both bindings were green (the
    concrete-first discipline) — not a guessed abstraction. It is also the seam where a knowledge
    layer (D3FEND/ATT&CK/OCSF) would eventually **generate** bindings instead of these hand-authored
    two, and the carrier of the ``technique`` that the next step, verdict-emission, needs.

    Kept deliberately specific (a *fan-out* binding, not a general ``StreamBinding``): a general
    binding type should emerge only when a second *detector family* (e.g. MI coordination, which
    needs two value-streams) forces a second binding shape.
    """

    name: str
    entity_field: str
    value_field: str
    grain_seconds: float
    technique: str
    alpha: float = 1e-3


#: Source IP → many accounts. ATT&CK T1110.003 (Brute Force: Password Spraying).
PASSWORD_SPRAY = FanoutBinding(
    name="password-spray",
    entity_field="Client_Address",
    value_field="Account_Name",
    grain_seconds=600,
    technique="T1110.003",
)

#: Account → many service tickets. ATT&CK T1558.003 (Kerberoasting); also catches the
#: pass-the-ticket class (T1550.003), which shares the fan-out signature.
SERVICE_TICKET_FANOUT = FanoutBinding(
    name="service-ticket-fanout",
    entity_field="Account_Name",
    value_field="Service_Name",
    grain_seconds=600,
    technique="T1558.003",
)


def run_binding(path: str, binding: FanoutBinding, *, loader=load_kerberos_events) -> dict:
    """Load the corpus under ``binding`` and run :func:`detect_fanout` — one detection, fully
    specified by the binding. Returns ``detect_fanout``'s dict with the ``binding`` attached.

    ``loader`` is the corpus-specific telemetry binding (signature
    ``(path, *, entity_field, value_field) -> list[(seconds, entity, value)]``); it defaults to
    :func:`load_kerberos_events` and is swapped for :func:`detection.cloudtrail.load_cloudtrail_events`
    to run the *same* fan-out detector over a different corpus. Only the loader is corpus-specific —
    the bucket/entropy/conformal machinery is not, which is the point the third binding demonstrates.
    """
    events = loader(
        path, entity_field=binding.entity_field, value_field=binding.value_field
    )
    res = detect_fanout(events, grain_seconds=binding.grain_seconds, alpha=binding.alpha)
    res["binding"] = binding
    return res


def distinct_value_counts(
    events: "list[tuple[float, str, str]]", *, grain_seconds: float
) -> dict[tuple[str, int], int]:
    """Per ``(entity, time-bin)`` cell, the **count of distinct values** — the trivial-baseline
    statistic the conformal-entropy fan-out is measured against. Reuses the same materialized
    :func:`bucket_fanout` grain, so the baseline and the entropy detector see the *same* cells."""
    return {key: len(set(vals)) for key, vals in bucket_fanout(events, grain_seconds=grain_seconds).items()}


def detect_by_distinct_count(
    events: "list[tuple[float, str, str]]", *, grain_seconds: float, threshold: int
) -> set[str]:
    """The **trivial baseline**: flag any entity with a cell touching more than ``threshold`` distinct
    values. No population, no calibration — just a fixed domain-informed cut. Returns the flagged
    entities.

    This exists to answer a long-open question honestly: *does the conformal-entropy detector beat
    plain ``distinct-count > k``?* The answer is corpus-dependent. On a large standing population
    (30-day Kerberos, ~10⁴ cells) conformal earns its distribution-free guarantee; on a single short
    burst (BOTS CloudTrail, ~10 cells) conformal is underpowered (its floor ``1/(n+1)`` sits far above
    a useful ``alpha``) and this threshold — which encodes a human prior the conformal test does not
    have — wins. The trade is explicit: distribution-free rigor (conformal) vs a domain assumption
    (the threshold). See ``test_cloudtrail.py``.
    """
    return {
        entity
        for (entity, _b), c in distinct_value_counts(events, grain_seconds=grain_seconds).items()
        if c > threshold
    }


def fanout_verdict(
    detection: FanoutDetection, binding: FanoutBinding, *, distinct_threshold: int = 5,
    exchangeability: Four = NONE,
) -> DetectionVerdict:
    """Emit the canonical :class:`~forge_core.DetectionVerdict` for one detected fan-out cell —
    closing the loop: real telemetry → binding → detection → the schema-validated verdict. Custody
    is honestly ``NONE`` (unsigned corpus); the W-record grounds who (the entity) and when (the time
    bin). The shared, honest projection lives in :func:`~detection._verdict.emit_detection_verdict`.

    **Cross-check (the redundant-primitive *check* role, mechanics only).** The primary detector is
    entropy/conformal; the *independent* measure is the cell's **distinct count** (``cell.distinct >
    distinct_threshold``). Their kjoin is carried as the verdict's ``cross_check``: agreement preserves
    the decision, disagreement → ``BOTH`` (a soundness alarm — the two should track since entropy is the
    spread of that cardinality; a divergence means the distribution *shape* departed from what the count
    implies). That a disagreement is *operationally* meaningful is a deferred claim (they are correlated,
    so disagreement is rare — see ``design/primitive_roles.md``); this wires the carrier, not its value.
    """
    distinct_check = TRUE if detection.cell.distinct > distinct_threshold else FALSE
    return emit_detection_verdict(
        f"{binding.name}|{detection.cell.entity}|{detection.cell.bin}",
        technique=binding.technique,
        pvalue=detection.pvalue,
        params={
            "entity": detection.cell.entity,
            "bin": detection.cell.bin,
            "technique": binding.technique,
        },
        check=distinct_check,  # independent fan-out measure → cross_check carrier
        # calibration evidence: the detection thresholded a conformal p-value at the binding's alpha →
        # distribution-free FAR ≤ alpha (marginal). Already computed; attached, not recomputed.
        calibration=Calibration("conformal", binding.alpha),
        # the conformal FAR ≤ alpha bound is BOUNDED only if exchangeability holds; the monitor verdict
        # (computed once over the calibration in fanout_verdicts) gates the tier — TRUE earns bounded.
        exchangeability=exchangeability,
        # `when` is the TEMPORAL ∀-validate fold's verdict; fan-out runs NO temporal recognition, so it is
        # honestly NONE (unanswered), not the TRUE default — claiming a validation that never ran would be
        # the None-vs-True drift the substrate exists to prevent. decision = kjoin(detect, NONE) = detect.
        when=NONE,
    )


def _calibration_exchangeability(cells: "list[FanoutCell]") -> Four:
    """The exchangeability monitor verdict over a run's calibration: the cell entropies in time order
    (the conformal calibration population). TRUE = no calibration drift detected; NONE = too few cells."""
    scores = np.array([c.entropy for c in sorted(cells, key=lambda c: c.bin)], dtype=float)
    return exchangeability_monitor(scores)


def fanout_verdicts(result: dict) -> "list[DetectionVerdict]":
    """One :class:`~forge_core.DetectionVerdict` per detected cell in a :func:`run_binding` result
    (which carries the ``binding`` and thus the technique). The exchangeability monitor is computed ONCE
    over the run's calibration (all cells) and gates each verdict's BOUNDED tier."""
    binding = result["binding"]
    exch = _calibration_exchangeability(result["cells"])
    return [fanout_verdict(d, binding, exchangeability=exch) for d in result["detected"]]
