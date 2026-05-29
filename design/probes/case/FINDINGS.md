# CASE / UCO probe — findings (2026-05-29)

Probed the live ontologies (shallow clones of `casework/CASE` + `ucoProject/UCO`;
see `fetch.sh`; clones gitignored). Goal per the downgraded gate: skim for reusable
PROV+SHACL-over-cyber **modeling patterns**, not conformance.

## What CASE/UCO actually are
- **UCO** (Unified Cyber Ontology) — the parent. Action-centric upper ontology: root
  `core:UcoObject`, composition via `core:Facet` + `core:hasFacet` (inverse-functional),
  rich `action:Action` (performer / instrument / object / result / participant / environment
  / location / startTime / endTime / error / subaction / actionStatus).
- **CASE** — forensics/investigation profile of UCO. Recently moved to **Linux Foundation**
  (maturity signal). `investigation.ttl` is the substance (328 lines); `master/case.ttl` is
  just an import aggregator (29 lines).

## Five concrete findings

1. **OWL + SHACL dual-typing is the core pattern.** Every class is declared as BOTH
   `owl:Class` AND `sh:NodeShape`, with `sh:targetClass` self-referencing and `sh:property`
   constraints inline. OWL carries semantics (subClassOf), SHACL carries validation. Classes
   *are* shapes. (UCO `core.ttl` has 119 such hits.)

2. **CASE RE-IMPLEMENTS PROV-O — it does not import it.** Zero `prov:` triples in either
   ontology. `investigation:wasDerivedFrom` / `investigation:wasInformedBy` are explicitly
   *"A re-implementation of the wasDerivedFrom/wasInformedBy property in W3C PROV-O"* in their
   own namespace, with `rdfs:comment` citing the PROV-O spec. So even the poster-child for
   "PROV-O over cyber" did NOT adopt `prov:` — it re-minted the concepts. "Speak the standard"
   wasn't followed by CASE itself.

3. **Provenance = `InvestigativeAction` + `ProvenanceRecord`.** `InvestigativeAction
   ⊑ uco-action:Action` (the activity). `ProvenanceRecord ⊑ core:ContextualCompilation` (a
   grouping) links an investigative action to the observations/items it produced, with
   `exhibitNumber` / `rootExhibitNumber` as chain-of-custody identifiers. Forensics-specific
   (custody chronology, exhibits) — heavier than canon's computation-provenance need.

4. **Generator-validator testing via PASS/XFAIL SHACL example pairs.** `tests/examples/` ships
   `X_PASS_validation.ttl` + `X_XFAIL_validation.ttl` for every concept — a positive instance
   that must pass SHACL and a negative that must fail. This IS canon's self-falsifying /
   generator-validator discipline, operationalized. The single most actionable borrow.

5. **Action ≈ richly-elaborated `prov:Activity`; UcoObject+Facet = object+facets composition.**
   Useful reference shape for canon's Entity/Activity, but UCO's is forensics/observable-heavy.

## Verdict for canon

**Do NOT adopt CASE/UCO wholesale** — confirmed:
- No compute layer (no DSP/detection) — orthogonal to forge-core.
- Representation layer is **forensics-investigation-shaped** (evidence, custody, exhibits,
  roles like Attorney/Examiner/Investigator) — a different emphasis than canon's
  detection/composition provenance. Overlap real but partial.
- CASE itself re-implemented rather than adopted PROV-O ⇒ "adopt CASE" was never the clean
  interop win; it's one opinionated forensics dialect, not a universal substrate. Reinforces
  the [[project-provenance-substrate-and-uco-gate]] downgrade.

**BORROW two methodology patterns** (both directly fix audit gaps):
- **OWL + SHACL dual-typing** — define canon's PROV/provenance classes (and semantic-core
  shapes) as `owl:Class` + `sh:NodeShape` together, constraints inline. Clean "semantics +
  validation in one artifact" = self-falsifying at the schema level.
- **PASS/XFAIL SHACL example pairs as the test discipline** — every provenance/op concept
  ships a passing and a failing instance validated by SHACL. This operationalizes the
  generator-validator pairing the audit found MISSING (`validation.py` unwired). Adopt as
  canon's self-falsifying test methodology.

**Decision data point for PROV:** CASE re-minted PROV-O in its own namespace; canon has *no*
reason to diverge (we want standard computation provenance, not a cyber-forensics dialect), so
canon should **import `prov:` directly** rather than re-implement — cleaner than CASE's choice.

## Net effect on the provenance design
No change to home/shape (new `provenance` package, PROV-O, lazy DAG). Refinement: the SHACL
self-falsifying layer should use **dual-typing + PASS/XFAIL example pairs** as its test
discipline, and **import `prov:` directly**. CASE is a reference for the SHACL methodology, not
a substrate to conform to.
