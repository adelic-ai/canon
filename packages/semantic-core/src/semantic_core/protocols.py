"""Typed surfaces semantic-core exposes to downstream packages.

`Lattice` is a structural Protocol by design, not a placeholder for an external
algebra library. FCA extraction needs a partial-order contract its consumers can
satisfy structurally; it does not need concrete algebra, and any typed-math
package that supplied one would still leave the elements to the caller.
"""

from __future__ import annotations

from typing import Hashable, Iterable, Protocol, runtime_checkable


ConceptId = str


@runtime_checkable
class Lattice(Protocol):
    """Partial-order lattice surface. Structural — implement it, don't inherit it."""

    def elements(self) -> Iterable[Hashable]: ...
    def leq(self, a: Hashable, b: Hashable) -> bool: ...
    def join(self, a: Hashable, b: Hashable) -> Hashable: ...
    def meet(self, a: Hashable, b: Hashable) -> Hashable: ...


@runtime_checkable
class Bridge(Protocol):
    """Cross-framework SKOS bridge — e.g. Sigma↔D3FEND, OCSF↔ATT&CK."""

    source_scheme: str
    target_scheme: str

    def map(self, source_id: ConceptId) -> Iterable[ConceptId]: ...


@runtime_checkable
class FrameworkAdapter(Protocol):
    """Loads a framework's catalog into the unified graph."""

    name: str

    def load(self) -> None: ...
    def concepts(self) -> Iterable[ConceptId]: ...
