"""Provenance core types — a lazy, content-addressed dataflow DAG.

Computation is described as a DAG built *before* anything runs. A node is a
*future value*; an op application records an edge for how that value is produced.
Computing the result is just one interpretation of the DAG (see
:mod:`provenance.interpret`); rendering its lineage, or — later — emitting PROV-O
RDF, are other interpretations over the same structure.

The model is the op-on-edge categorical one, and it *is* W3C PROV-O:

    Entity   = node = a value-position (object)            -> prov:Entity
    Activity = edge = an op firing (morphism)              -> prov:Activity
    params   = the recipe (op_name + sorted params)        -> prov:Plan

Two design properties hold here and are tested:

* **Lazy** — :func:`derive` records structure only; it never calls the kernel.
* **Content-addressed by derivation** — an Entity's id is the sha256 of its
  *construction* (op_name, params, parent ids), not its data. Identical sub-DAGs
  share an id, so an interpreter can dedup/memoise them for free. Source identity
  is by *reference* (an explicit ``name``) or, for anonymous sources, by the
  payload's object identity — we never hash large payloads.

The kernel is an opaque ``Callable`` and is excluded from identity, so this
package stays domain-agnostic: it never imports forge-core and does not know what
a Signal is. It is a generic lazy-dataflow + lineage engine.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

_ID_LEN = 16


def _hash(*parts: str) -> str:
    """Stable short content address over null-delimited string parts."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:_ID_LEN]


@dataclass(frozen=True, slots=True, eq=False)
class Activity:
    """An op firing — the edge / morphism (``prov:Activity``).

    Records how an output value is produced: the op name, the recipe (``params``,
    a sorted tuple → a hashable ``prov:Plan``), the input Entities (``prov:used``),
    and the opaque ``kernel`` that computes it. The kernel is excluded from
    identity — two firings of the same op with the same params on the same inputs
    are the same Activity regardless of which callable object backs them.
    """

    op_name: str
    params: tuple[tuple[str, Any], ...]
    used: tuple["Entity", ...]
    kernel: Callable[..., Any] = field(repr=False)

    @property
    def id(self) -> str:
        return _hash(
            "act",
            self.op_name,
            repr(self.params),
            *(u.id for u in self.used),
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Activity) and other.id == self.id

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass(frozen=True, slots=True, eq=False)
class Entity:
    """A value-position — the node / object (``prov:Entity``).

    A *future* value. A **source** carries a concrete ``payload`` and no producer
    (a raw input); a **computed** entity stays lazy, carrying only the
    :class:`Activity` that will produce it. Identity is by ``producer.id`` for
    computed entities and by reference/label for sources (never by hashing the
    payload). Equality and hashing are by ``id`` — same content address means the
    same node.
    """

    producer: "Activity | None" = None
    payload: Any = field(default=None, repr=False)
    kind: str | None = None
    label: str | None = None
    source_id: str | None = None

    @property
    def is_source(self) -> bool:
        return self.producer is None

    @property
    def id(self) -> str:
        if self.producer is None:
            ref = (
                self.source_id
                if self.source_id is not None
                else f"obj:{id(self.payload):x}"
            )
            return _hash("src", ref)
        return self.producer.id

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Entity) and other.id == self.id

    def __hash__(self) -> int:
        return hash(self.id)

    def value(self) -> Any:
        """Evaluate this entity's DAG and return the concrete value."""
        from provenance.interpret import evaluate

        return evaluate(self)


def source(
    payload: Any,
    *,
    name: str | None = None,
    kind: str | None = None,
    label: str | None = None,
) -> Entity:
    """Wrap a raw input as a source :class:`Entity`.

    Identity is by ``name`` when given — two sources with the same name share an
    id and dedup — otherwise by the payload's object identity (process-local;
    anonymous sources backed by distinct objects do not dedup). The payload is
    never hashed.
    """
    return Entity(
        producer=None,
        payload=payload,
        kind=kind,
        label=label or name,
        source_id=name,
    )


def derive(
    op_name: str,
    kernel: Callable[..., Any],
    used: "tuple[Entity, ...] | list[Entity]",
    params: Mapping[str, Any] | None = None,
    *,
    kind: str | None = None,
    label: str | None = None,
) -> Entity:
    """Build the :class:`Activity` + lazy output :class:`Entity` for an op call.

    Records structure only — the ``kernel`` is **not** invoked here (laziness).
    ``params`` is normalised to a sorted tuple so the Activity id is a stable
    content address independent of call-site kwarg order. The returned Entity's
    id equals its producer Activity's id (single-output assumption).
    """
    items = tuple(sorted((params or {}).items()))
    activity = Activity(
        op_name=op_name,
        params=items,
        used=tuple(used),
        kernel=kernel,
    )
    return Entity(producer=activity, kind=kind, label=label)
