"""Provenance-seam integration — forge-core ops produce well-formed provenance.

The unit tests in the per-op modules check that ops build Entities and evaluate
correctly. These check the *point* of the Phase 3 migration: that applying a real
forge-core op yields a lazy node whose lineage emits valid PROV-O and conforms to
the self-falsifying SHACL shapes, that the build-time kind gate fires at call,
that a declared array input (matched-filter template) shows up as a lineage edge,
and that the lock-in phase is a CYCLIC Signal circular_mean can consume.
"""
import numpy as np
import pytest

from forge_core import circular_mean, ops
from forge_core.signal import Signal, SignalKind

from provenance import Entity, evaluate, to_prov, validate


def _noise(n=256, seed=0):
    return np.random.default_rng(seed).exponential(1.0, n)


def test_op_returns_lazy_entity_then_evaluates():
    ca = ops.get("ca_cfar")
    node = ca(Signal(samples=_noise(), fs=1.0), guard=2, train=8)
    assert isinstance(node, Entity)            # lazy: nothing computed yet
    out = evaluate(node)
    assert set(out) >= {"threshold", "detections", "alpha"}


def test_op_lineage_emits_conforming_prov():
    node = ops.get("energy_detector")(Signal(samples=_noise(512), fs=1.0), nperseg=64)
    from rdflib.namespace import PROV

    g = to_prov(node)
    # the op firing is recorded as a prov:Activity ...
    assert len(list(g.triples((None, None, PROV.Activity)))) >= 1
    # ... and the derivation is well-formed provenance (self-falsifying check).
    assert validate(node).conforms


def test_build_time_kind_gate_fires_at_call():
    c = Signal(samples=np.ones(64, dtype=complex), fs=1.0, kind=SignalKind.COMPLEX)
    with pytest.raises(TypeError):
        ops.get("ca_cfar")(c)                  # rejected when the DAG is built


def test_template_is_a_lineage_input():
    from rdflib.namespace import PROV

    s = Signal(samples=_noise(256), fs=1.0)
    node = ops.get("matched_filter")(s, template=np.hanning(16))
    g = to_prov(node)
    # signal + template -> two prov:used edges into the matched_filter activity.
    assert len(list(g.triples((None, PROV.used, None)))) == 2


def test_lockin_phase_is_cyclic_and_circular_mean_consumes_it():
    fs, f0, n = 1000.0, 50.0, 8192
    t = np.arange(n) / fs
    x = np.cos(2 * np.pi * f0 * t + 0.7)
    out = ops.get("lock_in")(Signal(samples=x, fs=fs), freq=f0, bandwidth=2.0).value()
    phase = out["phase"]
    assert phase.is_cyclic
    # the Phase 0 + Phase 3 arc end to end: circular stats consume the phase.
    mid = phase.with_samples(phase.samples[n // 4 : 3 * n // 4])
    assert circular_mean(mid) == pytest.approx(0.7, abs=0.2)
