"""pySHACL wrapper — the self-falsifying layer at the graph level.

A SHACL shapes graph is the executable form of "this data is well-formed."
Every domain bridge ships shapes; every loaded ontology gets checked against
them. That is the substrate-self-falsifying commitment at the graph layer.

Scope note (2026-07-24): this is a **general** SHACL wrapper over arbitrary
``(data, shapes)`` graphs, and the richer of canon's two — it parses results
into structured :class:`Violation` objects (focus node / path / message /
severity). It is a **library utility, not on the live detection emit path**:
verdict/guarantee validation runs through ``provenance.shacl`` (which
materializes a derivation as PROV-O and ships the package's own well-formed
shapes, but returns no parsed violations). Kept here as the semantic-layer
SHACL tool — reach for it when you need parsed violations over an arbitrary
graph. The two are complementary, not redundant; don't "consolidate" this away
onto ``provenance.shacl`` without first porting the violation parsing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pyshacl
import rdflib

from semantic_core.graph import Graph


SH = rdflib.Namespace("http://www.w3.org/ns/shacl#")


@dataclass(frozen=True)
class Violation:
    focus_node: str | None
    source_shape: str | None
    result_path: str | None
    message: str | None
    severity: str | None


@dataclass
class ValidationReport:
    conforms: bool
    violations: list[Violation] = field(default_factory=list)
    text: str = ""
    results_graph: Any = None


def validate(data: Graph | rdflib.Graph, shapes: Graph | rdflib.Graph) -> ValidationReport:
    data_g = data.rdflib_graph if isinstance(data, Graph) else data
    shapes_g = shapes.rdflib_graph if isinstance(shapes, Graph) else shapes

    conforms, results_graph, text = pyshacl.validate(
        data_graph=data_g,
        shacl_graph=shapes_g,
        inference="none",
        advanced=False,
    )

    return ValidationReport(
        conforms=conforms,
        violations=_parse_violations(results_graph),
        text=text,
        results_graph=results_graph,
    )


def _parse_violations(results_graph: rdflib.Graph) -> list[Violation]:
    query = """
        PREFIX sh: <http://www.w3.org/ns/shacl#>
        SELECT ?focus ?shape ?path ?msg ?sev WHERE {
            ?r a sh:ValidationResult .
            OPTIONAL { ?r sh:focusNode ?focus }
            OPTIONAL { ?r sh:sourceShape ?shape }
            OPTIONAL { ?r sh:resultPath ?path }
            OPTIONAL { ?r sh:resultMessage ?msg }
            OPTIONAL { ?r sh:resultSeverity ?sev }
        }
    """
    return [
        Violation(
            focus_node=str(row[0]) if row[0] is not None else None,
            source_shape=str(row[1]) if row[1] is not None else None,
            result_path=str(row[2]) if row[2] is not None else None,
            message=str(row[3]) if row[3] is not None else None,
            severity=str(row[4]) if row[4] is not None else None,
        )
        for row in results_graph.query(query)
    ]
