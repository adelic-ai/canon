"""rdflib loader + SPARQL surface.

Thin wrapper. Exposes only the operations downstream packages actually need:
load turtle from a string or file, run a SPARQL query, serialize back out.
Vendor objects (`rdflib.Graph`, `rdflib.query.Result`) leak through on
purpose — re-wrapping them would be friction without payoff.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import rdflib


class Graph:
    """Owns one rdflib.Graph; merges multiple sources into it."""

    def __init__(self) -> None:
        self._g = rdflib.Graph()

    @property
    def rdflib_graph(self) -> rdflib.Graph:
        return self._g

    def load_turtle(self, source: str) -> "Graph":
        self._g.parse(data=source, format="turtle")
        return self

    def load_file(self, path: str | Path, format: str | None = None) -> "Graph":
        path = Path(path)
        self._g.parse(source=str(path), format=format or _guess_format(path))
        return self

    def query(self, sparql: str) -> rdflib.query.Result:
        return self._g.query(sparql)

    def serialize(self, format: str = "turtle") -> str:
        return self._g.serialize(format=format)

    def __len__(self) -> int:
        return len(self._g)

    def __iter__(self) -> Iterable[tuple]:
        return iter(self._g)


def _guess_format(path: Path) -> str:
    suffix = path.suffix.lower()
    return {
        ".ttl": "turtle",
        ".owl": "xml",
        ".rdf": "xml",
        ".xml": "xml",
        ".nt": "nt",
        ".jsonld": "json-ld",
        ".json": "json-ld",
    }.get(suffix, "turtle")
