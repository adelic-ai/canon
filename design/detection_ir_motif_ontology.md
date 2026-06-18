# Detection IR — a motif ontology with verified emitters

**Status: design + first slice BUILT, 2026-06-18.** §7's first slice is implemented in
`packages/detection/src/detection/motif.py` (+ `tests/test_motif.py`, 9 passing): two molecules
(`FieldMatch`/`Suppression`), `from_sigma` ingestion, two emitters (`eval_python` + `to_sparql`/`eval_sparql`),
`attest_emitter_agreement` (the gate — Python and SPARQL agree on **every** event of the OTRF corpus,
`coverage="true"`), and `record_selector_provenance` (the ground-truth selector is now a content-addressed
`prov:Activity`, closing §0). The rest below is the standing design. It
unifies four existing threads — Atlas (the primitive library), the OpenMath/OMDoc math-symbol stack,
the SKOS-graded mapping seam, and warrant-is-relational — and reframes the proposed Sigma→RDF ingestion
as its first concrete instance. Read and react before any build.

## 0. The provocation that started it

A throwaway `_comsvcs_positive()` finder — walk the events, grab the `EID1` whose `CommandLine` contains
`comsvcs`, GUID-join it to the `EID10` lsass read — was written to locate the labeled ground-truth instance
in OTRF, then discarded. Two objections, both correct:

1. **Discarding it violates canon's own thesis.** `warrant-is-relational`: trustworthiness lives in the
   *derivation*, not the result. That selector *is* how the label "this EID10 is the malicious read" was
   produced. Discard it and the label has an unwarranted step — "how did you know?" has no content-addressed
   answer. The selector's source belongs in the provenance DAG as the `prov:Activity` that derived the
   positive entity, so the label carries its own how. (It also already has a home: it is the
   dataset-generator's "scenario/piece" — emit-the-events and identify-the-ground-truth are one object, two
   directions. The discarded finder was a piece I failed to keep.)
2. **The language is incidental; the relation is the invariant.** `_comsvcs_positive` computes a *relation* —
   `spawn ⋈ access on ProcessGuid`. Python is the emitter; Rust would compute the same relation. What is
   load-bearing is the relation, not the syntax.

(2) is the seam. If the relation is the invariant and the language is the emitter, then detection logic wants
an **intermediate representation** that is the relation, with a per-language emitter on each side.

## 1. The unit is a molecule, not an atom

The right granularity is a recurring **composite**, not a single AST node.

- **Too atomic** — `field == value`, a string compare — and the IR is just an AST with no semantic content;
  you have re-implemented a parser and gained nothing.
- **Too coarse** — the whole rule — and nothing is reusable; you cannot share `spawn→access GUID-join` across
  the twelve rules that use it.

The useful unit is the **molecule** — `spawn→access GUID-join`, `LOLBin-endswith`, `distinct-value-fanout`,
`offhours-circular-dispersion`, `pairwise-MI-coordination`. The H2O analogy is exact: the **bond** is the
point. The join *key* (`ProcessGuid`) is what gives `spawn ⋈ access` emergent detection-semantics that
`field-equals` and `EID-filter` do not have alone — just as H2O's polarity is absent from H and O. A molecule
is a small bonded gadget with detection meaning; an atom is an operator with none.

**These molecules already exist in canon, un-named as such.** The primitive families *are* the catalog:
`fanout` (entity → distribution over values), `coordination`/MI (two streams → dependence), `subgraph`
`MotifSpec` (multi-EID structural join), field-match (`sigma_eval`). **Atlas** is meant to be exactly this
library — canonical uses + atypical uses + relations. So the IR is not new construction; it is giving the
primitives canon already has a **queryable RDF surface plus emitters**.

## 2. The IR is RDF; the molecule is a symbol; the language is a phrasebook

A detection in this IR is a **graph of molecule-symbols** — RDF, content-addressed. Each target language has
an **emitter** that maps symbols → that language's code. This is not a novel architecture; it is a proven one.

**The strong precedent — OpenMath / OMDoc / MMT** (canon's own mathabc thread). OpenMath *content
dictionaries* are a content-addressed ontology of mathematical operations; an OpenMath *object* is a graph of
those symbols; and every CAS has a **phrasebook** translating symbols → that system's code. That is precisely
"a code-symbol ontology that translates to any language" — already built and battle-tested for mathematics.
The detection-IR is **OpenMath phrasebooks for detection operations.** Same family, different domain:

- **pySigma backends** — Sigma AST → Splunk / KQL / ES|QL. The existing detection analogue.
- **CodeQL** — code as a relational IR, queried with one language, over many source languages.
- **Semgrep** — a single pattern matched across languages via a common AST.
- **MITRE CAR** — pseudocode → Splunk / EQL / Sigma.

So the architecture is known-good. The molecule ontology is the content-dictionary layer; the emitters are the
phrasebooks.

## 3. "Trivially translate to any language" is the part to delete

Structure ports trivially — the graph is just data. **Semantics do not.** This is exactly where OpenMath
phrasebooks are real work rather than a free lunch:

- Rust `ends_with` (byte semantics) vs Python `.lower().endswith()` (Unicode casefold).
- SPL `eventstats` (a streaming windowed aggregate) vs a pandas `groupby` (materialized).
- Null handling, case-insensitivity, timezone and ordering in the temporal join.

The honest version: **the RDF makes the structure language-agnostic; each emitter still needs per-target
semantic care and a check that the emit preserves meaning.** And that check is canon's own machinery — eating
its own tail:

> motif-IR → emit to language X → **attest the emit's fidelity** against a labeled corpus → *warranted* port.

Does the Rust emit cover the same labeled instances as the Python emit on a known corpus? That is exactly
`attest_fidelity` — coverage (Belnap) of an artifact against ground truth. So the canon-shaped claim is not
"trivial translation" but **verified translation**: language-agnosticism becomes a *fidelity-attested
property*, not an assumed one. The only words to strike from the original idea are "trivially / for free."

## 4. Sigma→RDF ingestion is the first emitter pair, not a separate project

The coverage map and the SPARQL-vs-code split both wanted a Sigma→RDF ingestion. In this frame it is a
**special case of the IR**, not a parallel effort:

- A Sigma rule **parses into a motif graph** (its `selection`/`filter` blocks become field-match and
  suppression molecules; a future correlation rule becomes a join molecule).
- `sigma_eval` (the in-memory interpreter) and pySigma (the query compiler) become **two emitters from the
  same graph** — not two independent implementations of "what the rule means." Their agreement on a corpus is
  a fidelity check between emitters (§3).
- Once rules are in RDF, the **knowledge-layer questions become SPARQL** — "which evaluable process_access
  rules claim T1003.001," the coverage/adjacency map, FCA/SKOS dedup of synonym rules — instead of bespoke
  Python globbing YAML off disk. (Per-event *firing* stays code, the hot path; only the *knowledge* queries
  move onto the graph. Same hot/cold split as everywhere.)

So the ingestion is the IR's proof-of-concept: one molecule vocabulary (field-match + suppression), two
emitters (`sigma_eval`, pySigma), one fidelity check between them, one SPARQL knowledge surface over the
parsed graph.

## 5. What this unifies

- **Atlas** gets its formal surface: the primitive library becomes the molecule ontology (content dictionary).
- **The dataset-generator** pieces and the discarded selector are the same thing as motifs run in the *emit*
  direction; a scenario is a motif graph with an "emit events" phrasebook.
- **The SKOS-graded seam** is how a molecule maps across schemas (OCSF data-side, Sigma rule-side) — a graded,
  justified, load-bearing-gated edge, not a free identity.
- **warrant-is-relational** is why the selector/emitter source must be content-addressed in the provenance:
  the derivation, including *which code computed the relation*, is part of the warrant.

## 6. Honest scope — what this is *not*

- It is **not** a universal transpiler. Cross-language semantic equivalence is undecidable in general; the IR
  buys *structural* portability and a *verification harness* (fidelity), not guaranteed equivalence.
- It does **not** subsume the per-event hot path into SPARQL (see §4) — firing stays code.
- The molecule vocabulary is **earned, not designed up front.** Extract a molecule only when ≥2 real
  detections share it (concrete-first, the same discipline as the `Binding` generalization). A speculative
  ontology of motifs nobody uses is the failure mode to avoid.
- "Any language" is **per-emitter work**, each emitter fidelity-gated before it is trusted (§3).

## 7. Smallest first slice (when build is greenlit)

1. Define the **molecule** dataclass + a tiny RDF serialization for two molecules only: `field-match`
   (the `sigma_eval` clause) and `suppression` (the filter block).
2. Parse the comsvcs Sigma rule into that motif graph (the **ingestion** — emitter pair input).
3. Two emitters from the graph: `sigma_eval`-shaped Python (already exists — wire it to consume the graph)
   and a SPARQL `ASK`/`SELECT` that answers "does this rule's molecule-set match this event's coordinate."
4. **Fidelity-attest the two emitters against each other** on the OTRF corpus — they must agree (Belnap
   `true`) on every labeled event, else the IR is lossy and the diff localizes where.
5. Content-address the motif graph + record the *selector* (`_comsvcs_positive`) as a `prov:Activity` in the
   verdict's provenance — closing the §0 hole.

Do **not** build the Rust emitter, the full molecule ontology, or correlation molecules first — those are
layers 2+. The first slice proves one thing: *one detection, two emitters, agreement attested.*
