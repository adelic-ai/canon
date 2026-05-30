"""provenance — a lazy, content-addressed dataflow + lineage substrate.

The canon-wide provenance core: computation is a DAG of Entities (value-positions)
and Activities (op firings) built before anything runs, PROV-O-shaped and
domain-agnostic. Build with :func:`source` / :func:`derive`; interpret with
:func:`evaluate` (compute), :func:`lineage` / :func:`explain` (render without
computing). The optional ``[rdf]`` extra (Phase 2) adds PROV-O emission and SHACL
validation as further interpreters. See
``~/canon/design/provenance_substrate_design.md``.
"""
from provenance.entity import Activity, Entity, derive, source
from provenance.interpret import evaluate, explain, lineage

__all__ = [
    "Entity",
    "Activity",
    "source",
    "derive",
    "evaluate",
    "lineage",
    "explain",
]
