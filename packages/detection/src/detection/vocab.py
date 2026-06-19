"""Vocabulary descriptor + coherence gate — the seam that makes OCSF normalization OFF-able.

A detection round fires ``events ⋈ rules`` by matching rule field names against event keys.
That only works when both sides speak the SAME field vocabulary; mix them (OCSF-rewritten
rules against native events, say) and every field lookup silently misses — a false-clean
NONE that looks like "nothing fired." So a round NAMES the vocabulary of its events and of
its rules and refuses to fire an incoherent pair.

``native`` (source-as-ingested events ⋈ native Sigma rules) is the default and the identity
setting: with both sides native the gate is a no-op and behavior is unchanged. OCSF/bespoke
normalization is an opt-in that swaps one or both sides onto a shared target vocab — the
gate is what keeps that opt-in from silently mis-firing. See
``design/ocsf_ingest_normalization.md`` for the full three-point spectrum (native / ocsf /
bespoke) on this one seam.
"""

from __future__ import annotations

from dataclasses import dataclass

NATIVE = "native"
OCSF = "ocsf"


@dataclass(frozen=True)
class Vocabulary:
    """The field vocabulary a stream of events, or a set of rules, is expressed in.

    ``name`` is the vocabulary identity that coherence is judged on (``native``/``ocsf``/a
    bespoke name). ``schema`` optionally pins the concrete schema/version behind the name
    (e.g. ``"ocsf-1.3"``); schema variants under one name are the mapping layer's concern,
    not this gate's.
    """

    name: str = NATIVE
    schema: str | None = None

    def __str__(self) -> str:
        return self.name if self.schema is None else f"{self.name}({self.schema})"


def vocab_name(v: "Vocabulary | str") -> str:
    """The identity a vocabulary coheres on — its ``name`` (or the bare string itself)."""
    return v.name if isinstance(v, Vocabulary) else str(v)


def coheres(a: "Vocabulary | str", b: "Vocabulary | str") -> bool:
    """Two vocabularies cohere iff a field name means the same thing on both sides — i.e.
    they share a ``name``."""
    return vocab_name(a) == vocab_name(b)


class VocabularyMismatch(ValueError):
    """Raised when a round is asked to fire rules against events of a different vocabulary."""


def require_coherent(events_vocab: "Vocabulary | str", rules_vocab: "Vocabulary | str") -> None:
    """Refuse an incoherent ``(events, rules)`` vocabulary pair — loudly, before firing, so a
    mismatch is an error rather than a silent all-NONE round."""
    if not coheres(events_vocab, rules_vocab):
        raise VocabularyMismatch(
            f"incoherent vocabulary pair: events speak '{vocab_name(events_vocab)}' but rules "
            f"speak '{vocab_name(rules_vocab)}'. Every field match would silently miss (a "
            f"false-clean NONE). Normalize one side onto a shared vocab, or run both native. "
            f"See design/ocsf_ingest_normalization.md."
        )
