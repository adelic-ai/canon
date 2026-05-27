# semantic-core

Typed wrappers over the W3C semantic stack plus FCA implication-basis extraction.

## Scope

semantic-core is the second layer of the canon stack (mathabc-core → semantic-core → forge-core). It does two things:

1. **Wraps off-the-shelf semantic infrastructure** — rdflib (graph + SPARQL), owlready2 (OWL DL reasoning), pySHACL (validation). Exposes Protocols at the boundaries so downstream packages don't bind to vendor APIs.
2. **FCA implication-basis extraction** — derives a minimum-primitive lattice from a concept graph. Output type is a `Lattice` instance (currently a local Protocol stub; will bind to `mathabc.order.Lattice` once mathabc-core is extracted).

Domain packages (`semantic-cyber`, future `semantic-geo`) sit downstream and supply their own ontologies + bridges.

## Module layout

- `graph` — rdflib loader + SPARQL surface
- `reasoning` — owlready2 wrapper for OWL DL entailment
- `validation` — pySHACL wrapper (the self-falsifying layer at the graph level)
- `fca` — formal concept analysis → implication basis → Lattice
- `bridges` — cross-framework SKOS bridge Protocol + helpers
- `protocols` — ConceptId, Lattice, Bridge, FrameworkAdapter typed surfaces

## Status

Scaffold only. No implementation yet.
