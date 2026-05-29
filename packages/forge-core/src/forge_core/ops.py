"""Op protocol and registry.

An Op is a named, pure transformation over a Signal. Ops register themselves by
name so analysis pipelines can be specified declaratively and discovered.

Ported from forge.core.ops largely as-is (step-0 verdict: PORT); only the import
path changed.
"""
from __future__ import annotations

from typing import Any, Callable, Protocol, runtime_checkable

from forge_core.signal import Signal


@runtime_checkable
class Op(Protocol):
    """A named transformation over a Signal.

    An Op takes a Signal and returns either another Signal or a derived value
    (scalar, array, dict). Ops must be pure: no mutation of the input.
    """

    name: str

    def __call__(self, signal: Signal, **params: Any) -> Any: ...


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


def _make_op(name: str, fn: Callable[..., Any]) -> Op:
    """Wrap a plain function as a named Op."""

    class _FnOp:
        def __init__(self) -> None:
            self.name = name

        def __call__(self, signal: Signal, **params: Any) -> Any:
            return fn(signal, **params)

    return _FnOp()


def op(name: str) -> Callable[[Callable[..., Any]], Op]:
    """Decorator: turn a function into a registered Op.

    Example
    -------
    >>> @op("mean")
    ... def _mean(sig, **_):
    ...     return float(sig.samples.mean())
    """

    def deco(fn: Callable[..., Any]) -> Op:
        return register(_make_op(name, fn))

    return deco
