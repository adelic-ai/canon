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

# The [rdf] extra (PROV-O emission + SHACL validation) is optional: the core
# stays dependency-free, so `import provenance` must work without rdflib. Expose
# these only when the extra's deps are present.
try:  # pragma: no cover - exercised by env with/without [rdf]
    from provenance.rdf import to_prov
    from provenance.shacl import (
        ValidationReport,
        validate,
        validate_graph,
        well_formed_shapes,
    )

    __all__ += [
        "to_prov",
        "validate",
        "validate_graph",
        "well_formed_shapes",
        "ValidationReport",
    ]
except ImportError:  # pragma: no cover
    pass
