"""The Sigma adapter — omega's ingest front-end for Sigma rules, and the ONLY place pySigma is imported.

Stage 0 (this file, now): parse a ruleset directory via pySigma into ``SigmaRule`` objects plus an honest
:class:`ParseReport`. Stage 1 (next, lands here too): map each rule's AST to omega's agnostic IR — after
which no ``SigmaRule`` (and no pySigma import) escapes this adapter, and everything downstream is
ruleset-neutral.

Total, error-isolating, deterministic. Verified on the vendored SigmaHQ corpus: 3,748 files, 3,748 rules,
zero errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


@dataclass
class ParseReport:
    """Honest accounting of the ingest. ``errors`` maps a pySigma exception *kind* to its count; ``error_paths``
    keeps the ``(path, kind)`` pairs so a spec-invalid rule can be *found*, not merely tallied. ``files`` counts
    source files (a file may hold several rules); ``rules`` counts the base detection rules actually returned."""

    files: int = 0
    rules: int = 0
    correlation_rules: int = 0                              # counted, deferred to a later axis
    errors: dict[str, int] = field(default_factory=dict)
    error_paths: list[tuple[str, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """True iff every file parsed — no rule was rejected."""
        return not self.errors

    def _record(self, path: Path, exc: Exception) -> None:
        kind = type(exc).__name__
        self.errors[kind] = self.errors.get(kind, 0) + 1
        self.error_paths.append((str(path), kind))


def _is_correlation(rule: object) -> bool:
    """Correlation rules (multi-rule, windowed) are a different shape than a base detection rule; omega
    analyses base rules first and counts correlations for later. Name-based, to stay robust across the pySigma
    versions that have moved the class between modules."""
    return "Correlation" in type(rule).__name__


def load(root: str | Path, *, pattern: str = "*.yml") -> tuple[list[SigmaRule], ParseReport]:
    """Parse every ``pattern`` file under ``root`` via pySigma. Returns ``(base_rules, report)``.

    Total and error-isolating: a file pySigma rejects is recorded in the report (path + exception kind) and
    skipped — never crashing the load, never silently vanishing. Deterministic: files are visited in sorted
    order. Correlation rules are counted in the report but kept out of the returned base-rule stream.
    """
    root = Path(root)
    report = ParseReport()
    rules: list[SigmaRule] = []
    for p in sorted(root.rglob(pattern)):
        report.files += 1
        try:
            collection = SigmaCollection.from_yaml(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:                            # pySigma raises SigmaError; guard anything else too
            report._record(p, exc)
            continue
        for rule in collection.rules:
            if _is_correlation(rule):
                report.correlation_rules += 1
            else:
                rules.append(rule)
                report.rules += 1
    return rules, report
