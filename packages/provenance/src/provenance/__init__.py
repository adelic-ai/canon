"""provenance — a lazy, content-addressed dataflow + lineage substrate.

The canon-wide provenance core: computation is a DAG of Entities (value-positions)
and Activities (op firings) built before anything runs, PROV-O-shaped and
domain-agnostic. Build with :func:`source` / :func:`derive`; interpret with
:func:`evaluate` (compute), :func:`lineage` / :func:`explain` (render without
computing). The optional ``[rdf]`` extra (Phase 2) adds PROV-O emission and SHACL
validation as further interpreters. See
``design/provenance_substrate_design.md``.
"""
from provenance.entity import Activity, Entity, derive, source
from provenance.interpret import evaluate, explain, lineage
from provenance.registry import OperationIdentityError, derive_registered
from provenance.carrier import (
    ALL,
    BOTH,
    FALSE,
    NONE,
    TRUE,
    Four,
    from_pair,
    kjoin,
    kmeet,
    leq_k,
    leq_t,
    neg,
    tjoin,
    tmeet,
)
from provenance.monotone import (
    assert_k_monotone,
    is_k_monotone_binary,
    is_k_monotone_unary,
)
from provenance.tier import Tier, tier_meet
from provenance.guarantee import Demotion, GuaranteeCertificate, guarantee
from provenance.custody import (
    CustodyAttestation,
    CustodyStep,
    Localization,
    custody,
    evidence_digest,
    localize,
)
from provenance.confidence import NO_EVIDENCE, Confidence, confidence
from provenance.validity import (
    UNCHECKED,
    VALID,
    Validity,
    malformed,
    trustworthiness,
)
from provenance.temporal import (
    All,
    Any,
    Before,
    Event,
    Never,
    Occurs,
    Pattern,
    Trace,
    Window,
    recognize,
)

__all__ = [
    "Entity",
    "Activity",
    "source",
    "derive",
    "derive_registered",
    "OperationIdentityError",
    "evaluate",
    "lineage",
    "explain",
    # carrier — the Belnap bilattice every fold computes in
    "Four",
    "NONE",
    "TRUE",
    "FALSE",
    "BOTH",
    "ALL",
    "from_pair",
    "leq_k",
    "leq_t",
    "kjoin",
    "kmeet",
    "tjoin",
    "tmeet",
    "neg",
    # the monotonicity gate (the acceptance test for a fold)
    "assert_k_monotone",
    "is_k_monotone_unary",
    "is_k_monotone_binary",
    # guarantee fold — the tier a result earned (honest by category)
    "Tier",
    "tier_meet",
    "guarantee",
    "GuaranteeCertificate",
    "Demotion",
    # custody fold — were the bytes tampered between entry and evaluation
    "custody",
    "CustodyAttestation",
    "evidence_digest",
    # custody localization — the backward exoneration walk over a multi-hop chain
    "CustodyStep",
    "Localization",
    "localize",
    # confidence fold — graded belief (Chair–Varshney LLR) + Belnap knowledge axis
    "confidence",
    "Confidence",
    "NO_EVIDENCE",
    # validity fold — source-payload well-formedness + the two couplings (trust + detection)
    "Validity",
    "VALID",
    "UNCHECKED",
    "malformed",
    "trustworthiness",
    # temporal fold — chronicle recognition (the §6 seam: negation under partial data)
    "recognize",
    "Pattern",
    "Trace",
    "Event",
    "Occurs",
    "Window",
    "Before",
    "Any",
    "All",
    "Never",
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
