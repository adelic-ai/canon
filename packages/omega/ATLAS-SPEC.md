# omega — MITRE ATLAS consume + coverage cartography (spec)

**Status:** spec, 2026-08. A self-contained omega enhancement — a new ingest + a new bridge axis,
using the existing IR / FCA / SKOS machinery. Not a rewrite.

**Goal:** extend omega to consume **MITRE ATLAS** (the adversarial-threat framework for AI systems —
ATT&CK's analog for AI/ML) and chart where existing detection knowledge **covers**, **diverges**,
and — mostly — **is silent** on the AI-threat landscape.

**Why now / why it stands alone:** this is the *general* cartography (map the AI-threat detection
landscape). It does **not** depend on agentwatch's detector being validated. What waits for that is
the *other* direction — mapping agentwatch's own coverage onto ATLAS — which is out of scope here.

---

## 1. Where it fits in omega

omega already lowers each rule language to one agnostic IR, projects it through axes, and joins
corpora on a shared spine (currently ATT&CK) via `omega bridge`. ATLAS slots into that shape:

- **ATLAS is a *spine*, not a corpus.** Like ATT&CK, it's a taxonomy the corpora get mapped *onto* —
  not a set of detection rules. So the work is a new **spine ingest** + a new **bridge axis**, mirroring
  how ATT&CK already works, plus the coverage read-out.
- Reuse `ir.py` (atoms, tags, `Source` provenance), `axes.py` (add an `atlas` axis), `fca.py` /
  `skos.py` (graded relations + Turtle), and the `bridge` join. **New code is one ingest adapter and
  one axis; everything above is unchanged.**

## 2. Data source

**`github.com/mitre-atlas/atlas-data`** — public, YAML. Prefer the compiled single file
`dist/ATLAS.yaml` (tactics, techniques `AML.Txxxx`, subtechniques, case studies, mitigations); fall
back to the `data/` source tree if the compiled form lacks a field. Public data, no sensitivity — no
scrub needed (unlike the agentwatch capsule work).

The one field that matters most for coverage: **ATLAS techniques that adapt or reference ATT&CK
techniques.** ATLAS reuses part of ATT&CK for AI-threats that manifest as traditional TTPs; those
cross-references are the bridge that lets existing Sigma/CAR coverage reach into ATLAS.

## 3. The work

### 3.1 ATLAS ingest adapter → IR
Parse `ATLAS.yaml` into omega's IR as spine nodes: technique id (`AML.Txxxx`), tactic, name,
description, subtechnique parentage, **and the ATT&CK technique ids it references** (the bridge).
Each carries a `Source` (provenance back to the ATLAS object id), same discipline as the Sigma/CAR
adapters.

### 3.2 ATLAS as a bridge axis
Add `atlas` to `axes.py`. Extend the cross-corpus bridge so a detection rule reaches an ATLAS
technique **transitively through ATT&CK**: rule → (its ATT&CK tags) → (ATLAS techniques that
reference those ATT&CK ids) → covered. A rule that directly carries an ATLAS tag (rare today) maps
directly.

### 3.3 Coverage cartography — the actual output
For every ATLAS technique, classify:
- **covered** — a Sigma/CAR rule reaches it (directly, or via the ATT&CK bridge);
- **silent** — no rule reaches it;
- **uncertain (CAR-coarse)** — the only would-be coverage runs through a CAR analytic whose query
  logic omega does not parse (§5). Reported separately from true silence.

Express as the graded SKOS/RDF omega already emits, plus a plain coverage table (technique →
status → the rules/tokens that cover it, if any).

## 4. The honest framing — "the silences are the map"

ATLAS is young and sparse, and **existing rule libraries barely target AI-threats**, so most of the
map will be silent. That is the finding, not a failure — but only if the silences are attributed
honestly:

- **Bridge-only coverage.** Coverage reaches ATLAS *only* where an ATLAS technique adapts an ATT&CK
  technique. Purely-AI techniques (prompt injection, model evasion, training-data poisoning) have no
  ATT&CK analog and are **silent by construction** — no traditional rule library addresses them.
  Label these distinctly: "silent — no ATT&CK bridge exists," not "silent — uncovered." They're
  different claims (the first is *structural*, the second is a *gap someone could fill*).
- **CAR coarseness (§5).** Silence that would be covered by CAR query logic omega can't see is
  `uncertain`, not `silent`.
- **Don't inflate coverage either.** A rule tagged with an ATT&CK technique that an ATLAS technique
  merely *references* is weak evidence it detects the *AI* manifestation. Mark bridge coverage as
  `bridged` (inherited), distinct from `direct` — bridged coverage is a lead, not a guarantee.

## 5. CAR is left coarse — deliberately (and its caveat)

CAR ingest stays as-is: structured axes (ATT&CK coverage, platforms, data-model refs) ingested; the
SPL/EQL/pseudocode query logic counted-but-unparsed (per omega's existing scope note). Consequence
for this work: an ATLAS technique whose only path to coverage is a CAR analytic's *query logic* will
read as `uncertain`, not `silent` or `covered`. The coverage table must carry that third state so a
CAR-caused blind spot is never reported as a real gap. Completing CAR is a separate future job.

## 6. Output & acceptance

- `omega atlas --sigma <sigma/rules> --car <car> --atlas <atlas-data>` → `out/atlas_coverage.json`
  (the table) + `out/atlas_coverage.ttl` (SKOS).
- **Acceptance:** counts print as `covered(direct) / covered(bridged) / uncertain(CAR) / silent(no-bridge) / silent(uncovered)`,
  summing to the ATLAS technique total. A run that reports high coverage is suspect — sanity-check
  it against the expectation that AI-native techniques are mostly silent.
- Provenance holds: every `covered` cell traces to the specific rule(s) and the bridge path.

## 7. Discipline

- Hands-off in **maude** (clone omega, build on a branch, integrate/push from the Mac). Public data
  only (ATLAS, Sigma) — no sensitivity, no scrub.
- Branch, atomic commits, record judgment calls in a DECISIONS/notes file. Add tests: the ingest
  against a small fixture slice of `ATLAS.yaml`; the bridge on a known ATLAS↔ATT&CK pair; the
  coverage classifier on a synthetic rule that should map `bridged` and one that should be `silent`.
- Don't complete CAR; don't map agentwatch's coverage (both out of scope).

## 8. Build order

1. ATLAS ingest adapter → IR (with ATT&CK references + provenance).
2. `atlas` axis + the transitive bridge.
3. Coverage classifier with the five-way status (incl. `uncertain(CAR)` and the two silences).
4. Output (JSON + SKOS) + the acceptance counts.
5. Write up the map honestly — lead with the silences and *why* each is silent.
