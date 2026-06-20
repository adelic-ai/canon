# The detection IR as a language — its vocabulary is stratified, and the strata ARE the Python/RDF boundary

**Status:** design note, 2026-06-20. Crystallizes a conversation thread: the detection IR is language-like, so
*what is its vocabulary?* The answer is that it has three vocabularies of very different character, and the
line between them is exactly the line between what should live in Python and what should live in RDF.
**Relates to:** [[project_detection_ir_motif_ontology]] (the IR-as-RDF / emitter-per-language plan),
[[project_skos_graded_mapping_seam]] (the open-field mapping seam), [[project_ocsf_ingest_normalization]]
(the data-plane waist), [[project_rust_emitter]] (the language-neutral wire form), the earned-tier-via-SHACL
mechanism in `packages/detection/src/detection/_verdict.py`.

## The IR is a formal language; vocabularies, not vocabulary

A `CompiledRule` is `rule_id + blocks (parsed molecules) + condition (a boolean/quantifier AST)`. Read as a
language, its tokens split — using the linguist's **closed class** (a small fixed set the language owns) vs
**open class** (borrowed, unbounded) — into three strata:

### 1. Closed class — the predicates and connectives (the language's OWN vocabulary)

- **Match predicates (verbs):** the supported-modifier set — `contains`, `startswith`, `endswith`, `eq`,
  `all`, `re`, `cidr`, `gt/gte/lt/lte`, `windash` (authoritative list: `sigma_eval.py` `_SUPPORTED_MODS`).
  ~a dozen, finite, canon-owned.
- **Composition operators (grammar/connectives):** `and`, `or`, `not`, the quantifier `(N | all | 1) of
  (glob | them)`, parens (grammar in `condition.py`; AST is plain tuples `('and'|'or', [nodes])`,
  `('not', node)`, `('ref', name)`, `('quant', …)`).
- **Values** are operands, not vocabulary (any literal).

This closedness is what makes it a *portable, faithful* IR. Two consequences follow directly:
- **Faithful emission.** The Rust emitter could be proven agreement-faithful because there are only ~a dozen
  verbs to reimplement. Natural languages have open verbs; a *formal* language closes them, and that closure
  IS the portability.
- **Evaluability is a vocabulary-closure problem.** Reaching 99.3% was literally "close the verb set"
  (modifier support + the condition parser). The 28 holdouts are verbs not yet admitted — `expand`,
  `fieldref`, `base64offset`, `wide` — not a structural limit.

### 2. Open class — the field names (borrowed from the log schema)

`Image`, `CommandLine`, `ParentImage`, `TargetImage`, `CallTrace`, `ServiceName`, `EventID`, … These are the
nouns the predicates operate on, and they come from the **platform's log schema** (Sysmon / Security / OCSF),
not from canon. Large, open, per-platform, externally evolving. This is precisely why the SKOS-graded mapping
seam exists: it is the impedance layer for "two platforms use different nouns for the same observable." You
never need a mapping seam for the predicates (you own them); you need it because the nouns are someone else's
vocabulary.

### 3. Semantic layer — the technique/tactic terms (borrowed from ATT&CK)

`T1003.001`, "credential-access", etc. These are not part of the detection-logic language — they are the
meaning *labels* an assembly claims, borrowed from ATT&CK the way fields are borrowed from the schema.
Vocabulary *about* an assembly, not vocabulary it is *written in* (a function's tags, not its syntax). This is
the layer the atom→technique→tactic→kill-chain stack hangs on.

## The stratification IS the Python/RDF boundary

The strata don't just describe the IR — they tell you where each piece should live, and why.

**Closed class → Python (and already is).** `_SUPPORTED_MODS` is a set, the AST is dataclasses/tuples,
`CompiledRule` is a dataclass. For a finite, canon-owned vocabulary of ~a dozen predicates and a handful of
connectives, a Python enum + AST is the *right* representation: fast, type-checked, no dependency. Do not
RDF-ify a fixed dozen operators.

**Open + semantic → RDF/SHACL/SPARQL.** You *can* model these in Python (it's Turing-complete; "can it" is
never the question). But you would rebuild four things and lose a fifth:
1. **Vendor vs reference.** OCSF fields and ATT&CK techniques are large, externally-owned, evolving. A Python
   enum is a *copy that goes stale*; RDF references the external vocabulary by IRI (mint/reference, don't
   vendor).
2. **Hand-rolled graph + query.** The payload is the *relationships* — atom↔technique (many-to-many),
   technique↔tactic (many-to-many), and the **graded** field mappings carrying a SKOS grade + a `.why()`
   justification + sub-scores (attributed edges). In Python you write `Edge` classes and bespoke traversal per
   question; that is SPARQL, reimplemented worse.
3. **Code-level vs data-level validation.** The "abstract class that controls correctness" (an OO instinct) is
   really a **SHACL shape**. A Python ABC validates *code* (methods exist); the thing you must validate is the
   emitted detection/verdict *graph* — **data**. SHACL validates data and is itself data (turtle you ship,
   diff, multi-conform against). The earned-tier mechanism already works this way (SHACL over the PROV-O).
4. **Language binding.** The motif-IR's reason to exist is *emit to many targets* (Python eval, Rust, SPARQL,
   pySigma). Vocabulary-as-Python-objects is Python-readable only; vocabulary-as-data (the `to_dict`/RDF wire
   form) is emitter-neutral. The Rust emitter already proves this.

## The deeper why — different first-class primitive, not "Python can't"

Python's native primitive is the **object and its references** — a tree of containment in one namespace. RDF's
native primitive is the **labeled edge** — a triple, a graph. You can build a graph out of objects, but then
the graph structure lives in *your code* (adjacency dicts, traversal, hand-rolled queries) instead of in the
*data*. Modeling the open/relational layer in Python doesn't fail; it **relocates the structure from the
representation into procedures you now own and maintain, and binds it to one language.** It is not
lower-dimensional — it is a different load-bearing primitive (object-tree vs edge-graph), and the open/semantic
layers are natively edge-graph (borrowed, many-to-many, attributed, queried, validated-as-data).

(All of RDF/RDFS/OWL/SHACL is text — Turtle `.ttl` files; SPARQL is the query language over them. So the
knowledge layer is human-readable, version-controlled, diffable text whose *meaning lives in the data*, the
direct contrast with structure-living-in-code.)

## The resulting architecture (formalizes "firing stays code, knowledge → SPARQL")

- **Closed evaluation core in Python** — predicates, the condition AST, `eval_ir`. Finite, fast,
  proof-checkable, the faithful firing path.
- **Open knowledge periphery in RDF** — field mappings (the SKOS seam), the technique/tactic graph, the graded
  edges, and the correctness **shapes** (SHACL) that earn the guarantee tier.

The two borrowed peripheries (field-vocab, ATT&CK-vocab) are *mappable* and external; the closed core is
*owned* and platform-independent. That is exactly why the IR is "the more important artifact": it is the one
layer whose vocabulary canon owns outright, so it is the stable, portable, proof-checkable center while the
two open vocabularies are the mapped, evolving edges.

## Implication for fault localization (the assembly-diagnosis thread)

The closed predicates are the *vouched primitives*: an atom that fires in other rules is corroborated by its
reuse. So a non-firing rule's fault is unlikely to be in a shared atom (that would break its siblings too) —
it localizes to the **assembly** (the composition/condition wiring) or to a *rule-unique, unvouched* atom (the
one-character-typo hiding place). The closed/open split is what makes this oracle work: the closed predicate +
the open field together form an atom whose correctness is checkable by reuse across the RDF technique graph,
while the assembly is the per-rule composition the diagnosis actually targets.

## Status

Design note, not a build directive. It records *why* the IR vocabulary is stratified and *where each stratum
should live*. The buildable consequence it points at is the IR-as-RDF emission (the motif-IR thread) with the
closed core staying in Python — to be picked up when a consumer (the assembly diagnosis, the technique/tactic
graph) actually needs the knowledge layer queryable.
