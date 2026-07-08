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
class Source:
    """Provenance — where a rule came from, fused to the rule and preserved under every transformation
    (the governing requirement, binding from adapter #2). ``ruleset`` is the origin corpus (``sigma`` /
    ``car`` / …); ``native_id`` is that corpus's own id (the Sigma UUID, the CAR id), retained verbatim and
    *decoupled* from whatever id omega assigns. So however omega restructures internally, the source stays
    trivially reachable — and after cross-ruleset dedup a merged concept can carry several of these."""

    ruleset: str
    native_id: str | None = None
    path: str | None = None
    version: str | None = None


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
    the analysis needs and nothing ruleset-specific left. ``logsource`` is an OPEN, sorted set of
    ``(dimension, value)`` pairs — only the dimensions the rule actually names (Sigma's ``category`` /
    ``product`` / ``service``, and extensible: a new logsource field is one more pair, not a broken tuple).
    It's a bag of orientation tags, not a positional triple. ``condition`` is retained verbatim as the
    provenance of the block polarities."""

    id: str | None
    title: str | None
    logsource: tuple[tuple[str, str], ...]
    tags: tuple[str, ...]
    blocks: tuple[Block, ...]
    condition: str
    source: Source | None = None       # provenance; adapters populate it, direct construction may omit it
