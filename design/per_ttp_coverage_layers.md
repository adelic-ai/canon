# Per-TTP coverage as a layered decomposition — atoms, compositions, catch-classes

**Status:** design, 2026-06-19. The rule-level layer (content-aware signature) is **built** (commit
`6591ac1`, on `main`); the atom layer and catch-class layer are **not built** (the latter is
synthcyber-gated). This doc records the framing the content-aware work surfaced.
**Relates to:** [[detection_ir_motif_ontology]] (the molecule = bonded gadget), [[self_validation_architecture]]
(the content-addressed DAG; the Belnap independence risk, §9), [[skos_graded_mapping_seam]] (the three grounds
for "what a rule detects": tag / IR-content / catch-set), [[sigma_consumption_audit]] (the redundancy
bracketing), [[project_detection_inversion_battery_framework]] (rules as N corroborating witnesses).

## The reframe

MITRE coverage is usually stated at the technique level — *"do we have ≥1 rule for T1003.001?"* That is the
wrong granularity. A technique is detected by a **set of distinct checks**, and "coverage" is a property of
that set, not a yes/no per technique. The content-aware signature work made this concrete: the field-set key
had been collapsing value-distinct checks into one concept and the round fired only one of them, silently
dropping the rest (OTRF T1003.001: 33 field-set concepts → 74 content concepts; 41 distinct detections were
being dropped at selection).

So per-TTP coverage is a **layered count**, and the layer you measure at determines what "covered" and
"redundant" mean.

## The three layers

```
atom            (field, op, value)                 — one predicate over one event        — SHARED across rules/TTPs
  │  bonded by AND / cross-event join on a key
molecule/rule   block(s) + condition               — a composition of atoms              — the authored unit
  │  grouped by what they catch
catch-class     rules that fire on the same instances — the true per-TTP variant set     — the ground truth
```

### Atom — the sub-detection primitive
A compiled clause `(field, op, values)`: *where* to look, *how* to compare, *what* against. E.g.
`TargetImage endswith \lsass.exe`. It is the smallest thing that is true or false on a single event, and it is
**shared**: `Image endswith \rundll32.exe` appears in dozens of rules across many techniques.

### Molecule / rule — the composition
A Sigma rule is a **composition of atoms**, not an atom. Structure:
- a **block** = an AND (or OR) of clauses — a molecule;
- a **cross-event bond** = a join of blocks on a shared key (`spawn ⋈ access on ProcessGuid`) — the
  motif-ontology unit, a molecule spanning events;
- a **condition** = the boolean / quantified / temporal composition over blocks (`selection and not filter`,
  `1 of sel_*`, sequence-within-window).

Elaboration varies. comsvcs is near-atomic (one block, three ANDed clauses). `selection and not filter` with a
quantifier is a genuine composition (a primitive plus an exclusion). So the corpus is a mix: some rules are
nearly bare primitives, others are elaborate compositions — there is no single "rule = primitive" assumption.

### Catch-class — the true variant count
Rules that fire on the **same labeled instances** are one variant of the detection, regardless of how they are
written. This is the only layer that measures real per-TTP coverage; it needs labeled instances across
channels/variants (the synthcyber/dataset-generator dependency).

## Where each concept key sits — and what it bounds

The keys we have are structural proxies that sit at different layers and **bracket** the truth:

```
key                what it collapses                  per-TTP effect                          redundancy
─────────────────  ─────────────────────────────────  ──────────────────────────────────────  ──────────
field-set          same fields (value-BLIND)          UNDER-counts variants (over-collapse)    UPPER bound (7.15x)
content signature  byte-identical (field+op+value)    enumerates at rule level; OVER-counts    LOWER bound (~1.0x)
                                                       equivalents written differently
catch-set          same instances caught              the TRUE variant count                   the real number
```

- **field-set** is value-blind, so it merges value-distinct checks → it *understates* the per-TTP variant set
  and *overstates* redundancy. It is the over-collapse upper bound.
- **content** collapses only byte-identical rules (≈none in a curated corpus), so it enumerates per-TTP at the
  rule level and *overstates* distinctness (two rules that catch the same thing written differently count as
  two) → the duplicate-only lower bound on redundancy.
- **catch-set** collapses by what each actually catches → the true variant count. Synthcyber-gated.

Consequence for coverage reporting: state per-TTP coverage as a **set of checks bounded by these keys**, not a
single number, until catch-set exists — content gives the honest upper bound on distinct checks, field-set the
lower bound; the truth is between.

## The shared-atom firing model (the engine lever)

A naive per-TTP sweep re-evaluates shared atoms many times: `Image endswith \rundll32.exe` is checked once per
rule that contains it, across every TTP swept. That is wasted work, and it is why "content-aware fires ~2× the
rules" reads as a cost — it is only a cost under a per-rule engine.

The fix factors the rules to their atoms:

```
1. collect the DISTINCT atom-set across all selected rules        (dedup is automatic — see below)
2. evaluate each distinct atom ONCE over the data → atom-truth cache   (event → {atom_id: bool})
3. evaluate each rule as a cheap boolean fold over the cache           (no re-touching the data)
```

**Content-addressing makes step 1 free.** An atom's `content_digest` *is* its node id, so identical atoms
across rules are one node — the Merkle dedup property. This is the IR-as-spine picture literally: atoms are the
leaves of the content-addressed DAG, compositions are internal nodes, and you evaluate the DAG once. It
dissolves the firing-volume worry: **more rules firing ≠ more atom evaluations** once atoms are shared. (Not
built — `eval_ir` is per-rule today, and `motif-rs` batches rules×events but still per-rule; atom-sharing is
the next factoring, and the scale architecture.)

## Redundancy as robustness vs correlation — why catch-set isn't the last word

Catch-set co-membership says two rules catch the **same target**. It does **not** say "drop one." Two rules
catching the same instance via different structure are **diverse paths to the same target**, and diversity is
robustness: if one rule's field is absent (telemetry gap), renamed (the OCSF/CallTrace impedance), blanked by a
naming mismatch, or evaded, the other still fires. That is N-version coverage / corroboration.

So redundancy has two axes, and the second decides whether it is worth keeping:

```
                       atom-overlap DISJOINT                 atom-overlap SHARED
                       (independent paths)                   (correlated paths)
same catch-class   →   ROBUST redundancy — keep both         WASTEFUL redundancy — no added robustness
                       (real corroboration; survives a       (and over-counts confidence in Belnap
                        telemetry gap / evasion / rename)      fusion — the shared-evidence risk, §9)
```

**Atom-overlap is the classifier**, and content-addressing supplies it: two rules share evidence iff they
share atoms (a shared sub-DAG). So the same atom factoring that makes firing cheap also tells you which
catch-set-redundant rules are *independent witnesses* (keep — they raise real confidence) versus *correlated*
(keep at most for readability — they do not). This closes the architecture's open independence question for
this domain: independence is decidable structurally, by atom-disjointness.

## The model in one picture

```
per-TTP coverage = a set of catch-classes
   each catch-class = one or more rules (compositions) that catch the same instances
      each rule    = a composition of atoms (clauses bonded by AND / join / condition)
         atoms are SHARED across rules and TTPs → evaluate once (content-addressed dedup)
   keeping >1 rule per catch-class is justified IFF their atoms are disjoint (independent witnesses)
```

- **field-set key** measures at the field layer → over-collapse, undercounts variants.
- **content key** (built) measures at the rule layer → honest upper bound on distinct checks; fixed the
  round's recall.
- **catch-set** measures at the catch layer → true variant count; synthcyber-gated.
- **atom factoring** (the DAG leaves) → the perf lever *and* the independence classifier; not built.

## Scope / status

- **Built:** the content-aware rule-level layer (`CompiledRule.content_digest`, `content_signature`), wired
  into `select_detections` and the audit. Recall fix proven (33→74 on OTRF T1003.001).
- **Not built — atom factoring:** evaluate the distinct atom-set once, cache, compose. Pure engine work,
  corpus-free; the content-addressed node id already exists (`content_digest` at the clause level would be the
  atom id — today `content_digest` is per-rule; an atom-level digest is the small addition).
- **Not built — catch-class:** the true per-TTP variant count and the same-catch grouping. Gated on the
  labeled-instance generator (synthcyber).
- **Open question this resolves once atom factoring exists:** witness independence for confidence fusion —
  decidable by atom-disjointness rather than assumed.
