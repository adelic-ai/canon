# omega

**FCA/SKOS rule-sameness over detection-rule corpora.** Given a body of detection rules (Sigma today, MITRE
CAR too), omega answers a deceptively hard question — *are these two rules the same?* The answer it gives is
that sameness is not absolute: it is **relative to a chosen semantic projection**, and omega makes that
projection the knob.

It lowers every rule to one ruleset-agnostic intermediate representation, derives the concept structure with
**Formal Concept Analysis**, and expresses the graded relations (`exact` / `broad` / `narrow` / `close` /
`related`) as a **SKOS** graph you can serialise to RDF. The result is reproducible from the corpus, not
asserted.

## Install

```bash
pip install -e .          # or: uv pip install -e .
```

One dependency: [pySigma](https://github.com/SigmaHQ/pySigma) (the official Sigma parser) plus PyYAML.
Python ≥ 3.11.

## Use

Point it at a Sigma checkout (`git clone https://github.com/SigmaHQ/sigma`):

```bash
python -m omega run --corpus path/to/sigma/rules --out ./out
```

```
ingest: 3748 files, 3748 rules, clean=True
omega over-collapse — 3748 rules
  projections:  blind=['field']  aware=['clause', 'polarity']
  corpus:  blind 592 concepts  ->  aware 3737  (split 6.31x)   biggest blind class: 416  aware residue: 11
  lattice edges by kind: {'related': 14728, 'broader': 78, 'narrower': 53, 'exact': 11, 'close': 17}
  ...per-product breakdown...
  generalizes (aware > blind in every slice): True
```

writing `out/figures.json` (the numbers) and `out/lattice.ttl` (the SKOS graph, SPARQL-able).

**The over-collapse**, in one line: keying rules on the *fields they read* (value-blind) folds 3,748 Sigma
rules into 592 "concepts" — a single concept swallows 416 distinct detections. Keying on *field + value +
polarity* (value-aware) tells 3,737 of them apart. The knob is the projection; nothing is privileged.

### Cross-corpus bridge

omega ingests more than one ruleset and joins them on a shared axis:

```bash
python -m omega bridge --sigma path/to/sigma/rules --car path/to/car
```

```
omega cross-corpus bridge — axis 'attack' over ['car', 'sigma']
  car      rules=  102  attack-tokens=  122  unique-to-it=10
  sigma    rules= 3748  attack-tokens=  633  unique-to-it=521
  pairwise shared: {'car~sigma': 112}   shared-by-all: 112   union: 643
  concrete joins (a shared token bridging the corpora):
    tag:attack.t1003    car=[CAR-2013-04-002, ...]  sigma=[3ec9a16d-..., ...]
```

ATT&CK bridges the two corpora for free (shared vocabulary); their *field* vocabularies do not (`exe` vs
`Image`) — that alignment is a graded mapping problem, deliberately left open.

## How it works

```
rulesets → ingest adapters → [ IR ] → axes → FCA concepts → SKOS relations → report
           (per ruleset)      waist    (the projection knob)
```

- **ingest/** — one adapter per rule language (Sigma via pySigma, CAR via its YAML). Ingest is inherently
  ruleset-specific; it is the *only* layer that is. Each adapter lowers to the IR and nothing above it knows
  a rule was ever Sigma.
- **ir.py** — the agnostic waist: polarity-tagged atoms `(field, mods, values)`, logsource as open
  `(dimension, value)` tags, ATT&CK tags, and a `Source` recording provenance (a rule always traces back to
  its origin id, whatever omega does internally).
- **axes.py** — the projection: `field` (value-blind) · `clause` (value-aware) · `polarity` (sign
  selection/filter) · `fieldref` (relational) · `logsource` · `attack`. Any subset is a valid notion of
  "same."
- **fca.py / skos.py** — concepts under a projection, then their graded relations + Turtle.

## Scope and limits

- **Structural, not behavioural.** omega compares what a rule *is*, not what it *catches*. Two structurally
  different rules can fire on the same events; that equivalence is invisible to structure and needs a runtime,
  which omega does not (yet) do.
- **Parse-for-clustering ≠ evaluate-for-firing.** Because pySigma parses the full spec, omega represents even
  rules it could not *execute* (base64, field-references, correlation) — they still yield attributes.
- **CAR is coarse (v1).** CAR analytics carry their logic as implementations in *other* query languages
  (SPL/EQL/pseudocode); omega ingests their structured axes (ATT&CK coverage, platforms, data-model
  references) and counts the unparsed query logic rather than dropping it.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The license covers omega's
code only, not the external corpora it reads (Sigma, CAR), which carry their own licenses.
