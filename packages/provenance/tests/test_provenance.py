"""Provenance core tests — build / evaluate / dedup / lineage / explain.

Toy kernels only; this package is domain-agnostic. Cover the two load-bearing
contracts (laziness, content-addressing) explicitly, since the whole substrate
rests on them.
"""
import pytest

from provenance import (
    Activity,
    Entity,
    derive,
    evaluate,
    explain,
    lineage,
    source,
)


# ── build & evaluate ─────────────────────────────────────────────────────────


def test_source_evaluates_to_payload():
    assert evaluate(source(42)) == 42


def test_derive_evaluates_chain():
    a = source(2, name="a")
    b = source(3, name="b")
    s = derive("add", lambda x, y: x + y, (a, b))
    assert evaluate(s) == 5


def test_params_are_passed_as_kwargs():
    x = source(10, name="x")
    scaled = derive("scale", lambda v, *, factor: v * factor, (x,), {"factor": 3})
    assert evaluate(scaled) == 30


def test_deep_chain_evaluates():
    e = source(1, name="seed")
    for _ in range(5):
        e = derive("inc", lambda v: v + 1, (e,))
    assert evaluate(e) == 6


def test_entity_value_method():
    assert derive("neg", lambda v: -v, (source(7, name="s"),)).value() == -7


# ── laziness (contract) ──────────────────────────────────────────────────────


def test_derive_does_not_call_kernel():
    calls = []

    def kernel(v):
        calls.append(v)
        return v

    derive("touch", kernel, (source(1, name="s"),))  # build only
    assert calls == []  # kernel never fired


def test_kernel_fires_only_on_evaluate():
    calls = []

    def kernel(v):
        calls.append(v)
        return v * 2

    node = derive("dbl", kernel, (source(5, name="s"),))
    assert calls == []
    assert evaluate(node) == 10
    assert calls == [5]


# ── content-addressing & dedup (contract) ────────────────────────────────────


def test_identical_derivations_share_id():
    a = source(2, name="a")
    one = derive("inc", lambda v: v + 1, (a,))
    two = derive("inc", lambda v: v + 1, (a,))
    assert one.id == two.id
    assert one == two  # equality is by id


def test_different_params_differ():
    x = source(10, name="x")
    p1 = derive("scale", lambda v, *, factor: v * factor, (x,), {"factor": 2})
    p2 = derive("scale", lambda v, *, factor: v * factor, (x,), {"factor": 3})
    assert p1.id != p2.id


def test_param_order_does_not_affect_id():
    x = source(1, name="x")
    k = lambda v, *, a, b: v  # noqa: E731
    assert (
        derive("op", k, (x,), {"a": 1, "b": 2}).id
        == derive("op", k, (x,), {"b": 2, "a": 1}).id
    )


def test_shared_subdag_computed_once():
    calls = []

    def expensive(v):
        calls.append(v)
        return v + 1

    seed = source(10, name="seed")
    shared = derive("expensive", expensive, (seed,))
    # A diamond: combine the same shared node with itself.
    root = derive("sum", lambda a, b: a + b, (shared, shared))
    assert evaluate(root) == 22
    assert calls == [10]  # the shared sub-DAG fired exactly once


def test_source_identity_by_name():
    # Same name dedups even with different payloads (identity is by reference).
    assert source(1, name="cfg").id == source(999, name="cfg").id
    # Anonymous sources backed by distinct objects do not dedup.
    assert source([1]).id != source([1]).id


# ── metadata passthrough ─────────────────────────────────────────────────────


def test_kind_and_label_carried():
    e = derive("mk", lambda: 1, (), {}, kind="signal", label="raw")
    assert e.kind == "signal"
    assert e.label == "raw"


def test_entities_usable_in_sets():
    a = source(1, name="a")
    dup = source(2, name="a")  # same id
    b = source(3, name="b")
    assert {a, dup, b} == {a, b}


# ── lineage & explain (render without computing) ─────────────────────────────


def test_lineage_topological_sources_first():
    a = source(2, name="a")
    b = source(3, name="b")
    s = derive("add", lambda x, y: x + y, (a, b))
    order = lineage(s)
    ids = [e.id for e in order]
    assert ids[-1] == s.id  # root last
    assert a.id in ids[:-1] and b.id in ids[:-1]  # sources before root
    assert len(ids) == len(set(ids)) == 3  # deduped


def test_lineage_does_not_compute():
    calls = []
    node = derive("boom", lambda v: calls.append(v) or v, (source(1, name="s"),))
    lineage(node)
    assert calls == []  # purely structural


def test_explain_renders_ops_without_computing():
    calls = []
    a = source(2, name="a")
    s = derive("add", lambda x, y: calls.append(1) or x + y, (a, source(3, name="b")))
    text = explain(s)
    assert "add" in text
    assert "source" in text
    assert calls == []  # explain never fires kernels
    assert text.count("\n") == 2  # 3 nodes -> 3 lines


def test_activity_id_equals_output_entity_id():
    s = derive("op", lambda v: v, (source(1, name="s"),))
    assert isinstance(s.producer, Activity)
    assert s.id == s.producer.id


def test_is_source_flag():
    assert source(1, name="s").is_source
    assert not derive("op", lambda v: v, (source(1, name="s"),)).is_source
