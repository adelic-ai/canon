"""Shared ingest types — the contract every adapter meets, ruleset-agnostic.

Each adapter (``ingest/sigma.py``, ``ingest/car.py``, …) exposes:

    load_ir(root) -> (list[CompiledRule], ParseReport)   # total · deterministic · accountable

and fills the *same* :class:`ParseReport`, so coverage is comparable across rulesets rather than each
adapter inventing its own accounting. Ruleset-specific counts (Sigma correlation rules, CAR unparsed
query-language implementations, …) go in the open ``deferred`` bag, not bespoke fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParseReport:
    """Honest accounting of an ingest pass. ``files`` = source files seen; ``rules`` = rules returned;
    ``deferred`` = a ruleset-agnostic bag of "seen but not fully analysed" counts (e.g.
    ``{"correlation": 2}`` for Sigma, ``{"unparsed-implementations": 99}`` for CAR); ``errors`` maps a parse
    exception *kind* to its count, with ``error_paths`` keeping ``(path, kind)`` so a bad rule can be found."""

    files: int = 0
    rules: int = 0
    deferred: dict[str, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)
    error_paths: list[tuple[str, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """True iff every file parsed — no rule was rejected."""
        return not self.errors

    def defer(self, kind: str) -> None:
        """Record one 'seen but not fully analysed' item under ``kind`` (ruleset-agnostic)."""
        self.deferred[kind] = self.deferred.get(kind, 0) + 1

    def record_error(self, path: Path, exc: Exception) -> None:
        kind = type(exc).__name__
        self.errors[kind] = self.errors.get(kind, 0) + 1
        self.error_paths.append((str(path), kind))
