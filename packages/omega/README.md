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

### ATLAS coverage cartography

**MITRE ATLAS** is ATT&CK's analog for AI-threats — a *spine*, not a rule corpus, like ATT&CK itself. omega
maps existing Sigma/CAR coverage onto it transitively, through the ATT&CK tags a rule already carries:

```bash
python -m omega atlas --sigma path/to/sigma/rules --car path/to/car --atlas path/to/atlas-data --out ./out
```

```
ingest: sigma 3137 rules, car 102 analytics, atlas 170 techniques (car deferred={'unparsed-implementations': 99})
atlas coverage — 170 techniques: covered(direct)=0 / covered(bridged)=26 / uncertain(CAR-coarse)=0 / silent(no-bridge)=136 / silent(uncovered)=8
```

writing `out/atlas_coverage.json` (the table) and `out/atlas_coverage.ttl` (the SKOS graph). (Run against the
live SigmaHQ/sigma and mitre-attack/car checkouts and the compiled ATLAS.yaml — reproducible, not asserted;
your own run's exact counts will drift as those corpora grow.)

**Read the silences, not just the coverage.** 136 of 170 ATLAS techniques (80%) come back silent — that's
the finding, not a gap in the build: existing rule libraries barely target AI-threats, and most ATLAS
techniques have no ATT&CK analog at all (prompt injection, model evasion, training-data poisoning, …), so no
ATT&CK-speaking corpus could reach them regardless of how complete it is. omega keeps that distinction
honest with **two different silences**: `silent(no-bridge)` (no ATT&CK reference exists — structural,
nothing to fill) vs `silent(uncovered)` (a reference exists, nothing reaches it — an actual gap; 8 of them
here). A third status, `uncertain(CAR-coarse)`, marks a technique whose only path to coverage runs through a
CAR analytic's unparsed query logic — a blind spot in what omega can verify, kept out of both `covered` and
`silent` rather than guessed either way (0 here — every CAR-reachable technique above is also Sigma-reached,
in this particular pair of corpora). A run that reports high coverage is suspect for exactly this reason —
here `covered` is 26 of 170 (15%), well under the CLI's half-the-total warning threshold.

## How it works

```
rulesets → ingest adapters → [ IR ] → axes → FCA concepts → SKOS relations → report
           (per ruleset)      waist    (the projection knob)
```

- **ingest/** — one adapter per rule language (Sigma via pySigma, CAR via its YAML), plus one *spine*
  adapter (ATLAS — a taxonomy, not a ruleset). Ingest is inherently source-specific; it is the *only* layer
  that is. Each adapter lowers to the IR and nothing above it knows a rule was ever Sigma.
- **ir.py** — the agnostic waist: polarity-tagged atoms `(field, mods, values)`, logsource as open
  `(dimension, value)` tags, ATT&CK tags, and a `Source` recording provenance (a rule always traces back to
  its origin id, whatever omega does internally). `AtlasTechnique` sits alongside `CompiledRule` for spine
  nodes — a taxonomy entry isn't a rule, and isn't forced to look like one.
- **axes.py** — the projection: `field` (value-blind) · `clause` (value-aware) · `polarity` (sign
  selection/filter) · `fieldref` (relational) · `logsource` · `attack` · `atlas` (direct ATLAS tagging).
  Any subset is a valid notion of "same."
- **fca.py / skos.py** — concepts under a projection, then their graded relations + Turtle.
- **coverage.py** — the ATLAS transitive bridge and its five-way honest-silence classifier (rule → its
  ATT&CK tags → the ATLAS techniques that reference them).

## Scope and limits

- **Structural, not behavioural.** omega compares what a rule *is*, not what it *catches*. Two structurally
  different rules can fire on the same events; that equivalence is invisible to structure and needs a runtime,
  which omega does not (yet) do.
- **Parse-for-clustering ≠ evaluate-for-firing.** Because pySigma parses the full spec, omega represents even
  rules it could not *execute* (base64, field-references, correlation) — they still yield attributes.
- **CAR is coarse (v1).** CAR analytics carry their logic as implementations in *other* query languages
  (SPL/EQL/pseudocode); omega ingests their structured axes (ATT&CK coverage, platforms, data-model
  references) and counts the unparsed query logic rather than dropping it. The ATLAS coverage cartography
  inherits this: a technique whose only path to coverage is CAR's unparsed logic reads `uncertain`, never
  silently upgraded to `covered` or downgraded to `silent`.
- **ATLAS coverage is bridge-only.** omega reaches an ATLAS technique through the ATT&CK tags a rule already
  carries — it does not (and, without runtime evaluation, cannot) verify that a rule detects the specifically
  *AI* manifestation of a shared ATT&CK technique. Bridged coverage is reported as a lead, not a guarantee.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The license covers omega's
code only, not the external corpora it reads (Sigma, CAR), which carry their own licenses.
