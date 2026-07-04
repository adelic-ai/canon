"""omega — FCA/SKOS rule-sameness over all of Sigma. Structure first, behavior later.

Layered around a ruleset-agnostic IR (the waist):

  ingest/       per-ruleset adapters (Sigma-specific today) — parse + lower to the IR
    sigma.py      Stage 0 ingest (pySigma) + Stage 1 map (later)
  ir.py         the agnostic IR: the atoms the analysis reads            (Stage 1's target)
  axes.py       the attribute knob: field-set / clauses / polarity / relational   (Stage 2)
  fca.py        concepts + subsumption order                             (Stage 3)
  skos.py       graded relations (exact/close/broad/narrow/related) + Turtle       (Stage 4)
  report.py     the over-collapse + generalization figures               (Stage 5)

Below the IR is ruleset-specific; at the IR the languages converge; above it omega is written once.
Parsing is delegated to the official parsers (pySigma for Sigma); omega owns the analysis.
"""
