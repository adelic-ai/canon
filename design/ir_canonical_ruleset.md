# The IR is the canonical ruleset — Sigma is a lowered frontend (the closure argument)

**Status:** design, 2026-06-19. Captures the closure argument and its consequences from the
atom-factoring / per-TTP discussion. The lowering (`compile_rule`) and atom factoring are
**built**; the IR-as-canonical posture, statistical atoms as first-class IR, the native
authoring surface, and the firing recommender are **not** (this names a deliberate fork).
**Relates to:** [[per_ttp_coverage_layers]] (the atom/composition/catch-class model this extends),
[[detection_ir_motif_ontology]] (the IR + emitters), [[self_validation_architecture]] (logic +
warrant fused in the content-addressed artifact; the arithmetic primitives where the
machine-checked tier lives), [[ocsf_ingest_normalization]] (the data-plane waist),
[[skos_graded_mapping_seam]] (tag / IR / catch-set grounds), [[sigma_consumption_audit]] (the
redundancy bracketing), [[project_abduction_loop_agent_design]] (uncovered anomalies → candidates).

## The closure argument — why you can't express statistics in Sigma, and why "precompute and threshold" games it

Sigma's expression algebra is closed under **boolean composition of field-predicates** (`contains`,
`endswith`, `re`, …), plus a **bounded count aggregation** (Sigma correlation: `event_count`,
`value_count`, `temporal`) compared to a threshold. It is **not closed** under the operations a
statistic needs — `divide` (proportion), `log₂`, `multiply`, `sum-over-buckets`. Shannon entropy is
`histogram(count) → divide → log₂ → multiply → sum → negate`; Sigma has the `count`, not the
arithmetic fold on top. So the function `raw events → entropy` is **inexpressible in Sigma's grammar**.

The common escape — *precompute entropy as a field, then a Sigma clause thresholds it
(`cmd_line_entropy|gte: 3`)* — does **not** close the algebra. It evaluates the arithmetic in a richer
algebra *outside* Sigma and **injects the scalar back as a 0-ary constant**. The algebra is unchanged;
you imported a literal. Two consequences, the second decisive for canon:

1. **The portability is illusory.** A Sigma rule's reason to exist is that it means the same thing on
   any backend. `cmd_line_entropy|gte: 3` is meaningless on any backend that didn't run *your exact*
   enrichment — so the rule isn't portable; it's a pointer to a non-standard, must-be-replicated
   computation.
2. **It splits the detection — and that is anti-canon.** The intelligence (entropy + conformal
   calibration) now lives in the enrichment; the Sigma rule is a hollow residue. canon's thesis is that
   **logic and warrant travel fused in the artifact** (the result *is* its justification). The trick
   breaks exactly that: the rule no longer carries the detection, and the verdict no longer carries the
   reasoning back to inputs. Standard SIEM practice (enrich-then-match), operationally fine — but it
   defeats the property canon exists to provide.

**The algebra, precisely (the Group-vs-Ring instinct, sharpened).** The instinct "*Sigma is a weaker
structure, not closed under what statistics need*" is correct; the labels aren't exact. Sigma ≈ a
**bounded/Boolean algebra over field-predicates** (one closure: boolean combination of matches) plus a
bounded count. Statistics need a structure with **arithmetic and a transcendental** (`+`, `×`, `÷`,
`log`). You cannot obtain a field's operations by importing constants into a lattice. "Precompute"
imports constants; it does not extend the operation set.

## The resolution — the IR is the canonical ruleset; Sigma is one lowered frontend

The IR already *is* the closed algebra: it has **both** match-ops (clauses) **and** the arithmetic
primitives (count, sum, divide, log₂, multiply, compare, rank — [[per_ttp_coverage_layers]] §1). So the
move is to make the **IR the canonical detection language**, and relate everything else to it:

- **Ingest Sigma as a faithfully-lowered frontend**, structure preserved — exactly `compile_rule`
  (typed blocks + condition AST; only the syntax is stripped). Sigma becomes a *source dialect*, not the
  authoring ceiling. The community corpus (thousands of detections) lowers in losslessly *for the part
  Sigma can express*.
- **Author statistical atoms natively in the IR** — entropy as a molecule of primitives, in the
  content-addressed DAG with provenance. The full computation **and** its warrant stay in the artifact:
  no smuggling, no split. This is where statistics belong because it is the only algebra closed under
  them.
- **Keep emitting Sigma for the match-expressible subset** — canon's boolean detections stay portable
  where Sigma *can* carry them. You don't discard Sigma; you **supersede it where it cannot reach** and
  ingest it where it can.
- **Content-addressed atoms ⇒ no true duplicates**, and the deduped atom-set + a **recommended firing
  scheme** is what the ruleset hands you (the atom factoring + the parked graph-structured firing).

So you do not game Sigma. You ingest it (lossless for what it says), and the IR is the home for what it
cannot — with logic and warrant kept together.

**Prior-art caution.** The value here is **closure + content-addressing + provenance**, *not* a new
syntax. The failure mode is building yet-another detection DSL. The IR must be a genuine intermediate
representation with Sigma (and KQL/SPL/CAR) as frontends and emitters, never a rival language. This is a
**deliberate fork** (a real build commitment), to be taken as such — not reflexively.

## Corollary 1 — the atom→TTP inverted index (routing + weighting)

Atoms are shared across rules; rules detect TTPs. So each atom carries an induced **TTP-set** — the
inverted index (atoms × TTPs). It is not bookkeeping:

- **Its spread is the atom's specificity — essentially IDF.** An atom in *many* TTPs is generic and weak
  evidence for any one (`Image endswith \rundll32.exe` spans T1003.001, T1218, …); an atom in *few* is a
  discriminator (`CallTrace contains comsvcs.dll` ≈ T1003.001). Firing a generic atom implies little;
  firing a near-exclusive one implies a lot. **The set size is the per-atom evidence weight** (the
  LLR/Chair–Varshney term), and it falls straight out of the index.
- **An atom *participates in* a TTP; it does not *detect* one.** The TTP is confirmed when its
  composition's atoms **co-fire** (the molecule). The index is membership/routing; firing is still the
  composition.
- **Membership has polarity.** An atom can be a positive selector *or* a negative filter (`not filter`,
  e.g. `User contains SYSTEM` as an exclusion). The atom→TTP edge is **signed** — supports vs excludes —
  or an exclusion would be miscounted as evidence-for.
- **Tag-claimed vs catch-set-grounded.** Deriving the TTP-set from rule *tags* inherits tag-lossiness
  (the 79-claim / 2-catch problem). The grounded version is "the TTPs whose *labeled instances* the atom
  fires on" (catch-set, synthcyber-gated). Two versions, the tag/IR/catch-set ladder again.

**What it buys:** the index *is* the recommended firing scheme — fire the distinct atoms once (the
artifact), then each fired atom's signed TTP-set routes to the candidate compositions, pruning to TTPs
whose atoms actually fired; the specificity gives the confidence weight for free.

## Corollary 2 — OCSF must be normalized to the real environment (a second reference frame)

OCSF the schema is the **possible**; the real environment is the **actual**. Source→OCSF (built) makes
data speak a common vocab but does not say what *this* environment populates. So there are **two
normalizations**:

1. source → OCSF (vocabulary) — the data-plane waist.
2. OCSF → environment-actual (grounding) — coverage/applicability judged against the OCSF attributes the
   environment *actually populates*, not the full schema.

**Coverage = the OCSF rule-set ∩ the environment's actual OCSF surface.** An atom reading
`process.cmd_line` is covered only if the normalized stream actually carries it; otherwise it is an
honest **NONE (missing telemetry)**, not coverage. The round already profiles the telemetry surface but
in *native* space; in OCSF mode applicability should be judged against the *normalized* surface, NONE-ing
rules that read unpopulated attributes. **Bespoke** lands here too: where the generic OCSF map is lossy
on a field load-bearing *for this environment*, tighten it environment-specifically. The schema is
generic; the grounding is per-environment.

## Status / buildables

- **Built:** `compile_rule` (Sigma → IR, structure-preserving); atom factoring (`detection/atoms.py` —
  the deduped atom-set + the atom-truth artifact, faithful to `eval_ir`); content-addressing (the
  no-true-duplicates property).
- **Immediate, low-regret:** the **atom→TTP inverted index** — annotate each atom with the signed
  technique-set of the rules it came from (tag-claimed now; grounded via catch-set later). Gives routing
  + specificity-weighting; builds directly on `collect_atoms`.
- **The fork (deliberate):** statistical atoms as first-class IR (entropy/MI/conformal as molecules of
  primitives); a native-IR authoring surface (write rules incl. stat-atoms directly); the firing
  recommender (graph-structured / killchain frontier-walk); OCSF-space applicability in the round.
- **Synthcyber-gated:** catch-set grounding (the true per-TTP variant count and the grounded atom→TTP
  weights).
