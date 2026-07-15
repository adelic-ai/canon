# omega

**A research instrument working toward one map of detection knowledge — the major rule libraries, where they
intersect and where they don't, resolved against MITRE ATT&CK.**

omega is a research instrument, not a finished product. Its destination: a navigable view of the major detection
libraries — Sigma, MITRE CAR, and more as adapters land — showing where they **overlap**, where they
**diverge**, and where each is **silent**, all mapped onto **MITRE ATT&CK** as the common spine. The end state
is a picture of *what detection knowledge exists* and how its pieces relate; this repo is the method being
built toward it.

Comparing detection libraries is harder than it looks, and the approach follows from two facts about why: the
rulesets are written in different languages, and *"are two detections the same?"* has no absolute answer — it
depends on how closely you look.

- **One agnostic representation (the waist).** Every rule, whatever its dialect, is lowered to a single
  ruleset-agnostic intermediate form; everything above reads only that — never a rule language — so a new
  library is a new *adapter*, not a rewrite of the analysis.
- **Sameness is a projection, not a verdict.** Two detections are "the same" only relative to a chosen
  semantic projection (which fields, which values, which context) — so omega makes that projection an explicit
  knob, and "same?" becomes a family of *graded* relations rather than a yes/no.
- **Structure derived, then expressed.** Formal Concept Analysis derives the concept structure from the
  corpus; the graded relations (`exact` / `broader` / `narrower` / `close` / `related`) are expressed as a
  **SKOS** graph, serialisable to RDF — reproducible from the rules, not asserted.

What follows is that method in use — the IR, the projection axes, the concept lattice, the cross-corpus bridge
on ATT&CK. The specific numbers are demonstrations of the machinery, not the thesis.

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

**Reading that output — the projection knob at work.** Keying rules on the *fields they read* (value-blind)
folds these Sigma rules into 592 "concepts," one of them swallowing 416 distinct detections; keying on *field +
value + polarity* (value-aware) tells 3,737 apart. Same rules, two projections, a ~6× swing in what counts as
"the same" — the machinery shown on one corpus, not a privileged verdict about it.

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
