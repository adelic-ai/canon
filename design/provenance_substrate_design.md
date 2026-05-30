# Canon provenance substrate — design + migration plan

> **⚠ SUPERSEDED IN PART (2026-05-30). READ `self_validation_architecture.md` FIRST.**
> This document's phased plan (Phases 0–6) was the provenance-only roadmap. Phases 0–4
> were **built** (circular stats, provenance core, [rdf] extra, forge-core lazy-op seam,
> semantic-cyber composition-link). The effort was then **reframed to FULL self-validation
> / kigimi** — provenance is now the *master joint* of a larger architecture (every
> cross-cutting concern a `≤_k`-monotone fold over one content-addressed DAG; chain of
> custody; honest guarantee tiers; the `~/canon/contracts/` narrow-waist base). **Phase 5
> here (semantic-core wiring) is subsumed, not the standalone next step.** Current
> direction: `self_validation_architecture.md` + `self_validation_v{1,2}_*.md` +
> `~/canon/contracts/`. The provenance facts below are still accurate as built; the
> "what's next" framing is not.

**Status:** proposed 2026-05-29. Decision committed: unified canon-wide, PROV-O-shaped,
full lazy DAG-primary, in a new sibling `provenance` package. **CASE/UCO gate cleared**
(2026-05-29) — do not adopt CASE/UCO; borrowed two methodology patterns (OWL+SHACL
dual-typing, PASS/XFAIL example pairs) and import `prov:` directly. Ready to build.

## Why

Audit (2026-05-29) found the provenance/lineage capability — the thesis's
"composition with mathematical provenance" — was specified in `forge_core_step0_audit.md:12`
("Artifact lineage … Port verbatim") and then **dropped** during the scaffold, and that
the gap is **canon-wide**:

- **forge-core** — 12 detection ops return bare dict/Signal, zero lineage.
- **semantic-core** — bridges / FCA / reasoning / SPARQL return bare values; `validation.py`
  calls itself "the self-falsifying layer" but `validate()` is never called outside tests.
- **semantic-cyber** — artifact-level provenance kept (`via_artifacts`, `SigmaRule.path`),
  but `detection_coverage` puts defenses and sigma rules side-by-side **unlinked** — the
  composition's "which rule validates which defense" is lost. Zero validators in source.

So this is not a forge-core feature. It is a substrate concern that lives *below* both the
semantic and the signal layers, and it should adopt a standard (W3C PROV-O) rather than a
bespoke `Artifact(op_name, parent_ids, kwargs)` schema.

## Core idea

Computation is described as a **DAG of nodes built before anything runs** (lazy,
DAG-primary). A node is a *future value*; an op application adds an edge that records how
that value is produced. A concrete value is **one interpretation** of the DAG; provenance
RDF, SHACL validation, cost, and planning are *other* interpretations over the same graph.

This is the **op-on-edge categorical** model — and it is exactly PROV-O:

```
prov:Entity   = node   = a value-position (object)
prov:Activity = edge   = an op firing (morphism), prov:used inputs, prov:wasGeneratedBy output
prov:Plan     = the recipe (op_name + params), via prov:qualifiedAssociation
prov:wasDerivedFrom = Entity→Entity derivation shortcut
```

## Package layout & dependency graph

New bottom-of-stack package. Light core has **zero heavy deps** so forge-core stays
numpy/scipy-only in its hot path; RDF/SHACL is an opt-in extra.

```
provenance/                 # NEW — pure Python core, optional [rdf] extra
  src/provenance/
    entity.py               # Entity, Activity, source(), derive(), content-addressed ids
    interpret.py            # interpreter protocol; evaluate(), explain()/lineage()
    rdf.py                  # [rdf] extra: to_prov() -> rdflib.Graph (PROV-O)
    shacl.py                # [rdf] extra: validate() -> ValidationReport (pySHACL)
    shapes/                 # SHACL shapes shipped by producers (self-falsifying)
  pyproject.toml            # deps = []; [project.optional-dependencies] rdf = [rdflib, pyshacl]

provenance  ─┬─►  forge-core        (deps: numpy, scipy, provenance)
             └─►  semantic-core     (deps: rdflib/pyshacl/owlready2, provenance)
                    └─► semantic-cyber
```

Build order: `provenance → semantic-core → semantic-cyber`, and `provenance → forge-core`.
The `[rdf]` extra deps rdflib/pyshacl **directly** (never semantic-core) → no cycle;
semantic-core may optionally consume the PROV graph to merge it with its domain graph.

## Core types (`provenance.entity`)

```python
@dataclass(frozen=True, slots=True)
class Activity:                       # the edge / morphism / op-firing
    op_name: str
    params: tuple[tuple[str, Any], ...]      # sorted -> hashable recipe (prov:Plan)
    used: tuple["Entity", ...]               # prov:used (inputs)
    kernel: Callable[..., Any] = field(compare=False, repr=False)  # opaque; not in identity
    @property
    def id(self) -> str:  # sha256(op_name, params, tuple(u.id for u in used))[:16]

@dataclass(frozen=True, slots=True)
class Entity:                         # the node / object / value-position
    producer: "Activity | None"       # None => source (raw input)
    payload: Any = None               # set ONLY for sources; computed entities stay lazy
    kind: str | None = None           # type tag — makes input_kind load-bearing (see below)
    label: str | None = None
    source_id: str | None = None      # explicit id for sources (identity by ref/label, not data)
    @property
    def id(self) -> str:  # source: sha256("src", source_id); computed: producer.id

def source(payload, *, name=None, kind=None, label=None) -> Entity: ...
def derive(op_name, kernel, used, params, *, kind=None, label=None) -> Entity:
    """Build Activity + output Entity LAZILY. No kernel call here."""
```

Key properties:
- **Lazy** — `derive` never runs the kernel; it only records structure.
- **Content-addressed by derivation, not data** (forge's principle kept): identical sub-DAGs
  share ids → free memoization/dedup at evaluate. Source identity is by reference/label
  (we do **not** hash large arrays); the *derivation* downstream is content-addressed.
- **Immutable** — interpreters never mutate Entities; `evaluate` keeps its own memo keyed by id.
- `kernel` is an opaque `Callable` so `provenance` stays domain-agnostic (it never imports
  forge-core or knows what a Signal is — it's a generic lazy-dataflow + lineage engine).

## Interpreters (`provenance.interpret`) — the multi-interpreter payoff

A DAG fold; the value is just one fold among many.

- `evaluate(entity) -> Any` — topological walk; call each `Activity.kernel(*realized_parents,
  **params)`; memoize by entity id; return the root value. (core)
- `explain(entity) -> str` / `lineage(entity) -> tuple[...]` — render the construction without
  computing. (core)
- `to_prov(entity) -> rdflib.Graph` — emit PROV-O triples (Entity/Activity/used/
  wasGeneratedBy/qualifiedAssociation→Plan). **Import `prov:` directly** — do NOT re-mint
  PROV terms in a canon namespace (see CASE probe outcome below; canon wants standard
  computation provenance, so it has no reason to diverge as CASE did). (`[rdf]`)
- `validate(entity, shapes) -> ValidationReport` — materialize PROV + run pySHACL. The
  **self-falsifying pairing**: each op ships a SHACL shape; validation checks the derivation is
  well-formed/sound. (`[rdf]`)
- *future:* `cost(entity)`, `simplify(entity)`, `plan(...)` — the attack-graph / detection-DAG
  payoff that DAG-primary unlocks (manipulate the graph before/without computing).

Convenience: `Entity.value()` calls `evaluate(self)`.

## CASE/UCO probe outcome — two borrowed patterns (`~/canon/design/probes/case/FINDINGS.md`)

The probe confirmed canon should **not** adopt CASE/UCO (no compute layer; forensics-shaped
representation; and CASE itself *re-implements* PROV-O rather than importing it — so it's one
opinionated dialect, not a universal substrate). But two of their methodology patterns are
borrowed here because both close gaps the audit found:

1. **OWL + SHACL dual-typing.** Define every provenance/op class as **both** `owl:Class` **and**
   `sh:NodeShape`, with `sh:targetClass` self-referencing and `sh:property` constraints inline.
   Semantics + validation live in one artifact → self-falsifying at the schema level. The
   per-op shapes `validate()` consumes are authored this way.
2. **PASS/XFAIL SHACL example pairs as the test discipline.** Every op/provenance concept ships
   a positive instance that must pass SHACL **and** a negative that must fail. This
   operationalizes the generator-validator pairing `semantic-core/validation.py` was missing,
   and becomes canon's standard self-falsifying test form (Phases 2–5).

**PROV decision (settled):** import `prov:` directly. CASE re-minted PROV-O because it had
domain reasons to diverge; canon does not.

## How an op-call looks (forge-core, after migration)

```python
x = source(Signal(...))                 # source Entity
f = butter(x, cutoff=30)                # Entity (lazy)  -- butter auto-sources a raw Signal too
e = energy_detector(f, nperseg=128)     # Entity (lazy)
d = ca_cfar(e, train=8)                 # Entity (lazy)

evaluate(d)            # NOW kernels run, topo order -> the ca_cfar dict
to_prov(d)             # PROV-O RDF of the whole chain
validate(d, shapes)    # SHACL self-falsifying check
explain(d)             # human-readable lineage
```

The kernels (`butter`, `energy_detector`, …) are **unchanged pure functions**
`fn(signal, **params) -> dict | Signal`. The `@op` decorator changes: calling an op builds an
`Entity` via `derive(op_name, fn, used, params)` instead of running `fn`. If given a raw
Signal/ndarray it auto-wraps in `source()`; if given an `Entity` it uses it. Always returns a
lazy `Entity`.

### input_kind becomes load-bearing (fixes a step-0 gap for free)

Each `@op` declares `accepts: tuple[kind,...]` and `produces: kind`. `derive` checks each
parent `Entity.kind` against `accepts` **at build time** → illegal compositions fail before
evaluation, at the protocol level (the step-0 audit flagged `input_kind` as "declared but
enforced nowhere"). The kernel keeps its `signal.require(...)` as a belt-and-braces eval-time
check.

## Migration plan (phased; full suite is the safety net at every step)

**Phase 0 — CyclicSignal phase-laundering fix (independent correctness bug, land first).**
step-0 audit's #1 real bug: phase/angle data is laundered into a `RealSignal`, causing ±π
branch-cut errors; `CyclicSignal` doesn't exist. Add the cyclic leaf / make `CYCLIC`
load-bearing on construction + circular-mean/variance aggregations. Independent of provenance;
sequenced first because it's a correctness defect and blocks correct ports.

**Phase 1 — `provenance` core package.** Entity/Activity/source/derive, content-addressed ids,
`evaluate`, `explain`/`lineage`. Tests: build/evaluate/dedup/explain on toy kernels.

**Phase 2 — `provenance[rdf]` extra.** `to_prov` (PROV-O) + `validate` (pySHACL) + a couple of
generic shapes. Tests: PROV-O triples well-formed; SHACL pass/fail behaves.

**Phase 3 — forge-core seam migration.** `@op` gains `accepts`/`produces` + builds Entities;
auto-source raw inputs; build-time kind gating. Migrate the 12 ops (kernels untouched) and
their tests (`op(sig, **p)` → `evaluate(op(sig, **p))` — mechanical). Optionally ship per-op
SHACL shapes (or defer to Phase 5).

**Phase 4 — semantic-cyber composition-link fix.** `derive_counters` / `defensive_coverage`
emit provenance; `detection_coverage` records the join as an Activity whose `used` is **both**
the defense set and the sigma-rule set, so "which rules + which defenses produced this
coverage" is preserved (closes the audit's composition-level gap).

**Phase 5 — semantic-core wiring.** bridges / FCA / reasoning emit provenance; **wire
`validation.py` SHACL in as the enforced paired validator** (not test-only). Ship shapes.

**Phase 6 — future interpreters.** `cost`, `simplify`, `plan` — the DAG-primary payoff for the
attack-graph / detection-DAG vision. Not in initial migration.

## Risks / decisions

- **Test-migration churn** (~130 detector call sites) — mechanical (`evaluate(...)` wrap); the
  passing suite gates each step.
- **Source identity** is by reference/label, not data-hash (avoid hashing big arrays);
  derivations remain content-addressed. Documented contract.
- **rdflib coupling isolated** to `provenance[rdf]`; forge-core's closure stays light.
- **Kernel-in-Activity** is an opaque callable (excluded from identity, not serialized);
  RDF emission uses op_name+params only.
- **Single-output ops** assumed (current ops return one value). Multi-output handled when a
  consumer needs it.
```
