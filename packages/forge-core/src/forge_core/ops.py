"""Op protocol and registry — the provenance seam.

An Op is a named transformation over a Signal. Calling an op does **not** run its
kernel: it records a node in the provenance DAG (``provenance.derive``) and
returns a lazy ``Entity``. The value is produced later by an interpreter —
``entity.value()`` / ``provenance.evaluate`` to compute, ``to_prov`` to emit
PROV-O, ``validate`` to SHACL-check. This makes provenance *unforgeable*: you
cannot apply an op without producing lineage (provenance Phase 3).

Three things the seam does at call time, none of which touch the pure kernel:

* **Auto-source** a raw ``Signal``/ndarray input into a source ``Entity`` (tagging
  its ``SignalKind`` so the gate below can see it); an ``Entity`` input is used
  as-is.
* **Build-time kind gate** — if the op declares ``accepts``, a raw-Signal input of
  the wrong kind raises ``TypeError`` *when the DAG is built*, not deep in a
  kernel at evaluate. This closes the step-0 "``input_kind`` enforced nowhere"
  gap. The kernel keeps its ``signal.require(...)`` as an eval-time backstop.
  (Output-kind propagation through op-chains is deferred — no consumer chains ops
  at the Entity level yet.)
* **Declared array inputs** — array-valued *inputs* (e.g. a matched-filter
  ``template``) named in ``inputs`` are pulled out of the params and sourced as
  their own ``used`` edges, so they appear in the lineage (``wasDerivedFrom``) and
  are not hashed into the content address. Everything else stays a recipe param.

The kernel itself is exposed as ``op.fn`` so one op can compose another *eagerly*
inside its kernel (lock-in low-passing its mixed product) without building a
throwaway sub-DAG.
"""
from __future__ import annotations

from typing import Any, Callable, Protocol, runtime_checkable

from provenance import Entity, derive, source

from forge_core.signal import Signal, SignalKind


@runtime_checkable
class Op(Protocol):
    """A named transformation over a Signal that builds a provenance node.

    Calling an Op returns a lazy ``provenance.Entity``; evaluate it (or
    ``entity.value()``) to get the Signal / derived value. Ops must be pure:
    no mutation of the input.
    """

    name: str
    fn: Callable[..., Any]

    def __call__(self, signal: Signal | Entity, **params: Any) -> Entity: ...


# ── registry ────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, Op] = {}


def register(op_obj: Op) -> Op:
    """Register an Op by its .name. Returns the op (usable as a decorator)."""
    if op_obj.name in _REGISTRY:
        raise ValueError(f"Op {op_obj.name!r} already registered")
    _REGISTRY[op_obj.name] = op_obj
    return op_obj


def get(name: str) -> Op:
    """Look up a registered Op by name."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"no Op registered as {name!r}") from None


def registered() -> list[str]:
    """Sorted list of registered Op names."""
    return sorted(_REGISTRY)


def _gate(kind: SignalKind, accepts: tuple[SignalKind, ...], op_name: str) -> None:
    """Build-time kind check, mirroring Signal.require at the op boundary."""
    if kind not in accepts:
        allowed = ", ".join(k.name for k in accepts)
        raise TypeError(
            f"op {op_name!r} requires signal kind in {{{allowed}}}, got {kind.name}"
        )


def _make_op(
    name: str,
    fn: Callable[..., Any],
    accepts: tuple[SignalKind, ...] | None,
    inputs: tuple[str, ...],
) -> Op:
    """Wrap a pure kernel as a lazy, provenance-building named Op."""

    class _FnOp:
        def __init__(self) -> None:
            self.name = name
            self.fn = fn  # the pure kernel, for eager intra-op composition
            self.accepts = accepts
            self.inputs = inputs

        def __call__(self, signal: Signal | Entity, **params: Any) -> Entity:
            primary = self._source_primary(signal)
            used: list[Entity] = [primary]
            # Pull declared array inputs out of params into their own used edges,
            # in declaration order (which matches the kernel's positional order).
            for key in self.inputs:
                val = params.get(key)
                if val is None:
                    continue
                params.pop(key)
                used.append(val if isinstance(val, Entity) else source(val))
            return derive(self.name, self.fn, tuple(used), params)

        def _source_primary(self, signal: Signal | Entity) -> Entity:
            if isinstance(signal, Entity):
                if (
                    self.accepts is not None
                    and signal.is_source
                    and isinstance(signal.payload, Signal)
                ):
                    _gate(signal.payload.kind, self.accepts, self.name)
                return signal
            if self.accepts is not None and isinstance(signal, Signal):
                _gate(signal.kind, self.accepts, self.name)
            kind = signal.kind.name if isinstance(signal, Signal) else None
            return source(signal, kind=kind)

    return _FnOp()


def op(
    name: str,
    *,
    accepts: tuple[SignalKind, ...] | None = None,
    inputs: tuple[str, ...] = (),
) -> Callable[[Callable[..., Any]], Op]:
    """Decorator: turn a pure kernel into a registered, lazy, provenance Op.

    Parameters
    ----------
    accepts:
        Allowed input ``SignalKind``\\s, gated at build time. ``None`` = no gate.
    inputs:
        Names of array-valued *input* params (e.g. ``("template",)``) to model as
        provenance ``used`` edges rather than recipe params. Listed in the order
        the kernel takes them positionally after the primary signal.

    Example
    -------
    >>> @op("mean", accepts=(SignalKind.REAL,))
    ... def _mean(sig, **_):
    ...     return float(sig.samples.mean())
    >>> _mean(some_signal).value()   # doctest: +SKIP
    """

    def deco(fn: Callable[..., Any]) -> Op:
        return register(_make_op(name, fn, accepts, inputs))

    return deco
