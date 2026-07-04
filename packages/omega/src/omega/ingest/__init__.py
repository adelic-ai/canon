"""ingest — the per-ruleset front-ends (the one ruleset-specific layer of omega).

Each detection ruleset has its own parser: Sigma via pySigma, CAR via its data-model YAML, Elastic via EQL,
Splunk ESCU via SPL. So ingest is *inherently* per-ruleset — one adapter module per language, each parsing
its own dialect and (from Stage 1 on) lowering it to omega's ruleset-AGNOSTIC IR. Below this layer everything
is ruleset-specific; at the IR the languages converge; above it (``axes``, ``fca``, ``skos``, ``report``)
omega is written once.

The contract each adapter satisfies:

    load(root) -> (rules, ParseReport)      # parse a ruleset directory — total, deterministic

Only :mod:`omega.ingest.sigma` exists today. ``car`` / ``elastic`` / ``escu`` slot in here when they are
needed — without reshaping anything above the IR.
"""
