"""An indexed view over the lowered corpus — for human lookup and browsing, not for analysis.

The order rules arrive in (sorted path) is arbitrary, and nothing meaningful is lost by it: each
:class:`~omega.ir.CompiledRule` already carries its taxonomy (``logsource``, ``tags``), so the folder
structure the paths encoded is fully recoverable. This wraps the flat list and exposes the lookups a human
wants — by id, by title, by logsource — while the *analytic* structure (which rules are the same / broader /
narrower) is what the FCA/SKOS stages PRODUCE, and is independent of this order.

Rule ids are unique; titles are NOT guaranteed unique in Sigma, so ``by_title`` maps to a *list*.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator

from omega.ir import CompiledRule


class Corpus:
    """A list of :class:`~omega.ir.CompiledRule` plus lookup indices. Iterable and positionally indexable
    (list-like), with ``by_id`` / ``by_title`` / ``by_logsource`` for the human's real access patterns."""

    def __init__(self, rules: Iterable[CompiledRule]) -> None:
        self.rules: list[CompiledRule] = list(rules)
        self.by_id: dict[str, CompiledRule] = {r.id: r for r in self.rules if r.id}
        titles: dict[str, list[CompiledRule]] = defaultdict(list)
        logsources: dict[tuple, list[CompiledRule]] = defaultdict(list)
        for r in self.rules:
            if r.title:
                titles[r.title].append(r)          # titles can collide -> list
            logsources[r.logsource].append(r)
        self.by_title: dict[str, list[CompiledRule]] = dict(titles)
        self.by_logsource: dict[tuple, list[CompiledRule]] = dict(logsources)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[CompiledRule]:
        return iter(self.rules)

    def __getitem__(self, i: int) -> CompiledRule:
        return self.rules[i]

    def get(self, rule_id: str) -> CompiledRule | None:
        """The rule with this id, or ``None``."""
        return self.by_id.get(rule_id)

    def titled(self, title: str) -> list[CompiledRule]:
        """All rules with this exact title (a list — titles are not unique)."""
        return self.by_title.get(title, [])
