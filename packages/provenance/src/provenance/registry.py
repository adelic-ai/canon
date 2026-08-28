"""Operation-identity registry — closes the op_name/kernel gap :func:`~provenance.entity.derive`
leaves open by design.

``derive()``'s ``Activity.id`` deliberately excludes the kernel from identity (see
``entity.py``'s module docstring): two independently-built recipes with the same
``op_name``/params/parents are meant to dedup to the same id even if they hold
different-but-behaviorally-identical kernel objects. That contract only stays safe
if ``op_name`` is *actually* 1:1 with one implementation — a promise ``derive()``
itself cannot enforce without breaking that dedup (``test_identical_derivations_share_id``).

:func:`derive_registered` enforces it at the layer where ``op_name``s are chosen
instead: it binds each ``op_name`` to the ``__code__`` of the first kernel it sees
and rejects any later call that reuses the name with a *different* code object. A
lambda literal re-evaluated on every call to its call site produces a new function
object each time but the same code object, so repeated legitimate calls never trip
this — only a second, distinct call site reusing the same name does. Mirrors
``forge_core.ops``'s existing ``register()``/``_REGISTRY`` ("one name, one Op"),
generalized for callers outside forge-core that build DAG nodes with raw ``derive()``.

**This is semantic binding, not memoization.** ``_REGISTRY`` is process-global and
grows monotonically for the life of the process — it never forgets an ``op_name``
once bound, and it is not scoped per-DAG, per-call, or per-test. That's *why* a
production ``op_name`` must be a real, stable, ideally package-qualified identifier
for one implementation (an operation identity), and *why* the provenance test
suite's generic names (``"add"``, ``"inc"``, ``"join"``, …) stay on raw ``derive()``
instead of this registry — reusing a generic name across independent test modules
here would collide across unrelated tests in the same pytest process, which is a
correctness problem for a semantic registry even though it's exactly the intended
dedup behavior for ``derive()`` itself.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import CodeType
from typing import Any, Callable

from provenance.entity import Entity, derive

_REGISTRY: dict[str, CodeType] = {}


class OperationIdentityError(ValueError):
    """Raised when an ``op_name`` already bound to one kernel is reused with a different one."""

    def __init__(self, op_name: str, prior: CodeType, attempted: CodeType) -> None:
        self.op_name = op_name
        self.prior = prior
        self.attempted = attempted
        super().__init__(
            f"op_name {op_name!r} is already bound to the kernel at "
            f"{prior.co_filename}:{prior.co_firstlineno} ({prior.co_qualname}); "
            f"refusing to rebind it to {attempted.co_filename}:{attempted.co_firstlineno} "
            f"({attempted.co_qualname}) — "
            "two different implementations would silently share one provenance id."
        )


def _kernel_code(kernel: Callable[..., Any]) -> CodeType:
    func = getattr(kernel, "__func__", kernel)
    return func.__code__


def derive_registered(
    op_name: str,
    kernel: Callable[..., Any],
    used: "tuple[Entity, ...] | list[Entity]",
    params: Mapping[str, Any] | None = None,
    *,
    kind: str | None = None,
    label: str | None = None,
) -> Entity:
    """Like :func:`provenance.derive`, but refuses to let ``op_name`` be rebound to a
    different kernel. Raises :class:`OperationIdentityError` on a mismatch instead of
    silently building an Activity whose id collides with an unrelated computation's."""
    code = _kernel_code(kernel)
    prior = _REGISTRY.setdefault(op_name, code)
    if prior is not code:
        raise OperationIdentityError(op_name, prior, code)
    return derive(op_name, kernel, used, params, kind=kind, label=label)
