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
* **Content-addressed by derivation** — an Entity's id is a real CID
  (:mod:`provenance.cid`, ``contracts/cid.md`` PIN 2) over its *construction*
  (op_name, params, parent ids), not its data. Identical sub-DAGs share an id, so
  an interpreter can dedup/memoise them for free. Source identity is by
  *reference* (an explicit ``name``) or, for anonymous sources, by the payload's
  object identity — we never hash large payloads. This dedup contract is why the
  kernel stays out of identity — see :mod:`provenance.registry` for the guard
  that keeps an ``op_name`` 1:1 with one implementation despite that.

The kernel is an opaque ``Callable`` and is excluded from identity, so this
package stays domain-agnostic: it never imports forge-core and does not know what
a Signal is. It is a generic lazy-dataflow + lineage engine.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from provenance.cid import recipe_cid


def evidence_digest(payload: bytes | str) -> str:
    """The **full** sha2-256 hex of evidence bytes — an evidence source's content digest.

    This is the digest that, under the keystone (cid.md PIN 4, custody.md), *is* the source
    CID and the in-toto product digest: ``source.id == evidence_digest(payload) ==
    in-toto product digest``. A plain sha256 hex digest, deliberately **not** wrapped as a
    :mod:`provenance.cid` CID like derived-node ids are, because it must equal a real in-toto
    sha256 product digest byte-for-byte. Only byte/str evidence is in scope — arrays are
    inputs, not evidence, and are never hashed for identity (cid.md)."""
    if isinstance(payload, str):
        b = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        b = bytes(payload)
    else:
        raise TypeError(
            f"evidence_digest needs bytes/str evidence, got {type(payload).__name__}"
        )
    return hashlib.sha256(b).hexdigest()


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
        return recipe_cid(self.op_name, dict(self.params), tuple(u.id for u in self.used))

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
    evidence_id: str | None = None
    reference: bool = False  # a knowledge/reference input (a rule, model, parameter), NOT evidence —
    # custody is about the evidence bytes, so reference inputs are excluded from the evidence-custody fold.

    @property
    def is_source(self) -> bool:
        return self.producer is None

    @property
    def is_evidence(self) -> bool:
        """A by-payload-digest (tamper-evident) source — its CID *is* its content digest."""
        return self.evidence_id is not None

    @property
    def is_reference(self) -> bool:
        """Reference/knowledge data (a rule, model, parameter) applied TO the evidence — not evidence
        itself. Its integrity is a separate concern (analytic provenance); it is custody-NOT-APPLICABLE,
        so the evidence-custody fold excludes it rather than dragging the verdict to ``NONE``."""
        return self.reference

    @property
    def is_ephemeral(self) -> bool:
        """A by-object-identity anonymous source (no ``name``, not evidence) — its id is
        process-local (``id(payload)``-derived) and will NOT match across a fresh process or a
        rebuilt DAG. Not reproducible/content-addressed; do not treat its id as durable."""
        return self.producer is None and self.evidence_id is None and self.source_id is None

    @property
    def id(self) -> str:
        if self.producer is None:
            # Evidence source: the CID IS the payload digest (the keystone — cid.md PIN 4).
            if self.evidence_id is not None:
                return self.evidence_id
            # By-reference source: id by name (or anon object identity); carries NO integrity.
            ref = (
                self.source_id
                if self.source_id is not None
                else f"obj:{id(self.payload):x}"
            )
            return recipe_cid("source", {"ref": ref}, ())
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
    evidence: bool = False,
    reference: bool = False,
) -> Entity:
    """Wrap a raw input as a source :class:`Entity`.

    ``reference=True`` marks a knowledge/reference input (a rule, model, parameter applied TO the
    evidence) — custody-not-applicable, so the evidence-custody fold excludes it (see :meth:`Entity.is_reference`).

    Two identity routes, the cid.md PIN 4 distinction:

    * **by-reference (default).** Identity is by ``name`` when given — two sources with the
      same name share an id and dedup — else by the payload's object identity (process-local;
      anonymous sources backed by distinct objects do not dedup). The payload is never
      hashed, and the id carries **no integrity guarantee** (a trusted handle, nothing more).
    * **by-payload-digest (``evidence=True``).** The keystone: the source's ``id`` *is* the
      sha2-256 digest of its byte/str payload, so ``source.id == evidence_digest(payload) ==
      the in-toto product digest == the root prov:Entity id`` — one hash, three roles. This
      is the only **tamper-evident** source identity; the custody fold verifies it by CID
      equality. Requires byte/str evidence (arrays are inputs, not evidence).
    """
    evidence_id = evidence_digest(payload) if evidence else None
    return Entity(
        producer=None,
        payload=payload,
        kind=kind,
        label=label or name,
        source_id=name,
        evidence_id=evidence_id,
        reference=reference,
    )


def ephemeral_source(payload: Any, *, kind: str | None = None, label: str | None = None) -> Entity:
    """A source with no durable identity: id is process-local object identity (:attr:`Entity.is_ephemeral`
    is ``True``). Never claim this participates in a cross-run reproducible/content-addressed result —
    rebuild the DAG in a fresh process and this node's id will differ. Equivalent to ``source(payload)``
    with no ``name``/``evidence``; named explicitly so a call site states its own reproducibility posture
    instead of it being implicit in which kwargs were omitted."""
    return source(payload, kind=kind, label=label)


def reference_source(name: str, payload: Any, *, kind: str | None = None, label: str | None = None,
                     reference: bool = False) -> Entity:
    """A by-reference source: id is the stable ``name`` (cid.md PIN 4 — identifies a *trusted handle*,
    carries NO integrity claim on its own). Equivalent to ``source(payload, name=name)``; named
    explicitly to make the by-reference (as opposed to ephemeral or evidence) identity route a
    deliberate call-site choice."""
    return source(payload, name=name, kind=kind, label=label, reference=reference)


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
