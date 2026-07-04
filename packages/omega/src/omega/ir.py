"""The IR — omega's ruleset-agnostic representation of a detection rule. The waist.

An ingest adapter (``ingest/sigma.py`` today) parses its dialect and lowers it to these dataclasses; from
here up — axes, FCA, SKOS, report — omega never sees pySigma or any ruleset-specific type. The IR carries
exactly what the analysis reads: the polarity-tagged atoms, the logsource, the tags, and the raw condition
(kept as provenance for the polarity call, and for any later refinement).

Frozen + hashable, so rules and their pieces compare and dedup by value.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Atom:
    """One ``field | modifiers : values`` test — the leaf the axes read. ``field`` is ``None`` for a keyword
    (whole-event) item. ``mods`` are the normalised modifier names (``endswith``, ``contains``, …); ``values``
    are the match values as strings. A rule's meaning at the finest grain is a set of these."""

    field: str | None
    mods: tuple[str, ...]
    values: tuple[str, ...]


@dataclass(frozen=True)
class Block:
    """A named detection block and its **polarity** — read from the condition: ``+1`` selection (the rule
    fires when this matches) or ``-1`` filter (the rule is suppressed when this matches). Both *narrow* the
    rule; the sign says from which side. This is where the essay's "filters are includable, polarity-tagged"
    becomes concrete."""

    name: str
    polarity: int
    atoms: tuple[Atom, ...]


@dataclass(frozen=True)
class CompiledRule:
    """omega's agnostic IR for one detection rule — produced by an adapter, consumed by the axes. Everything
    the analysis needs and nothing ruleset-specific left. ``logsource`` is ``(category, product, service)``;
    ``condition`` is retained verbatim as the provenance of the block polarities."""

    id: str | None
    title: str | None
    logsource: tuple[str | None, str | None, str | None]
    tags: tuple[str, ...]
    blocks: tuple[Block, ...]
    condition: str
