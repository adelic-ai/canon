"""Interpreters over the provenance DAG — the value is one fold among many.

A DAG fold. Computing the result (:func:`evaluate`) is one interpretation;
rendering the construction without computing (:func:`lineage`, :func:`explain`)
are others. Phase 2 adds ``to_prov`` (PROV-O RDF) and ``validate`` (SHACL) as
further folds over the same structure; this module holds the dependency-free
core ones.
"""
from __future__ import annotations

from typing import Any

from provenance.entity import Entity


def evaluate(entity: Entity) -> Any:
    """Compute the value of ``entity`` via a memoised topological walk.

    Each :class:`~provenance.entity.Activity` kernel is called once with its
    realised parent values and params; results are memoised by entity id, so a
    shared sub-DAG (a diamond) is computed exactly once. Sources return their
    payload directly. The memo is local to this call.
    """
    memo: dict[str, Any] = {}

    def visit(e: Entity) -> Any:
        eid = e.id
        if eid in memo:
            return memo[eid]
        producer = e.producer
        if producer is None:
            value = e.payload
        else:
            inputs = [visit(u) for u in producer.used]
            value = producer.kernel(*inputs, **dict(producer.params))
        memo[eid] = value
        return value

    return visit(entity)


def lineage(entity: Entity) -> tuple[Entity, ...]:
    """The construction in dependency order — sources first, ``entity`` last.

    A topological ordering of every Entity reachable from ``entity``, deduplicated
    by id. Renders the structure *without* computing anything.
    """
    order: list[Entity] = []
    seen: set[str] = set()

    def visit(e: Entity) -> None:
        if e.id in seen:
            return
        seen.add(e.id)
        if e.producer is not None:
            for u in e.producer.used:
                visit(u)
        order.append(e)

    visit(entity)
    return tuple(order)


def explain(entity: Entity) -> str:
    """A human-readable rendering of the DAG, one line per node, without computing.

    Each line is ``<id>  <op>(<params>)  <- [<parent ids>]`` for a computed node,
    or ``<id>  source  <label>`` for a source — in dependency order.
    """
    lines: list[str] = []
    for e in lineage(entity):
        producer = e.producer
        if producer is None:
            tag = e.label or e.kind or "source"
            lines.append(f"{e.id}  source  {tag}")
        else:
            params = ", ".join(f"{k}={v!r}" for k, v in producer.params)
            parents = ", ".join(u.id for u in producer.used)
            lines.append(f"{e.id}  {producer.op_name}({params})  <- [{parents}]")
    return "\n".join(lines)
