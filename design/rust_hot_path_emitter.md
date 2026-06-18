# Rust hot-path emitter — scope

**Status: scope, 2026-06-18. No code.** The next rung after the motif-IR first slice
(`design/detection_ir_motif_ontology.md`, BUILT). The motif graph already emits to Python (interpreter) and
SPARQL (oracle); this scopes the **third emitter — Rust — for the production firing path**, licensed by the
same agreement attestation. A genuine fork (a Rust toolchain enters the picture), so this is laid out for a
decision, not started. Recommendations are marked **▶**.

## 0. What it is, and what Rust actually buys (honestly)

The hot path is "fire thousands of rules over billions of events." The Python emitter is fine for *one rule
over a corpus* — `str.endswith` is C-speed in CPython — so **the per-predicate speedup is not the win, and
overselling it would be wrong.** What Rust buys is three things the Python path structurally can't:

1. **The dispatch loop.** Thousands of rules × N events is a pure-Python nested loop; that interpreter
   overhead (not the comparison) dominates. A compiled loop removes it.
2. **Parallelism.** `rayon` over cores is free data-parallelism on an embarrassingly-parallel problem (events
   are independent). CPython's GIL makes this awkward.
3. **The deployment shape.** A standalone Rust worker consuming a stream/shard *is* how the hot path deploys
   at scale — the same artifact serves both production and the attestation harness. SPARQL/Python never had a
   credible answer to "run this over a petabyte"; this does.

So the honest framing: Rust is the **throughput + parallelism + deployable-worker** emitter, not a magic
constant-factor on one comparison.

## 1. Emission strategy — interpreter vs codegen

Two ways to "emit to Rust":

- **(a) Interpreter-in-Rust.** A fixed Rust evaluator that reads the `MotifGraph` (serialized) as *data* and
  evaluates events — `sigma_eval`, recompiled native. No per-rule codegen, no runtime compiler.
- **(b) Codegen.** Generate Rust source per rule, compile a ruleset into a `cdylib`/binary — true phrasebook
  emission, monomorphized and branch-predictable.

**▶ Interpreter first.** (a) already captures the loop + parallelism + deployment wins at a fraction of the
complexity, with no runtime `rustc` dependency. (b) squeezes a further constant factor (no match-dispatch) but
adds a compile step, a toolchain at deploy time, and far more surface. Build (b) only if profiling the
interpreter shows dispatch is the bottleneck — the same *earned-not-designed* discipline as the molecule
vocabulary. Codegen is a layer-2 optimization, not the slice.

## 2. The boundary — how canon talks to Rust

- **(a) Subprocess / streaming.** A standalone Rust binary: reads the rule graph + events (JSONL on stdin /
  files), writes per-event firings (JSONL on stdout). Process-isolated, language-agnostic, no coupling to the
  Python package's build. Cost: serialization at the boundary — amortized by batching.
- **(b) PyO3 / maturin.** A Rust extension module called in-process from Python. Best per-call ergonomics, but
  pulls a Rust build into the Python package and a compiled artifact per platform.

**▶ Subprocess/streaming as primary.** It *is* the deployment model (a Rust worker over a shard/feed), and the
same invocation serves the attestation harness (pipe a corpus in, diff the firings against the Python oracle).
PyO3 is a later convenience binding for in-process/notebook use, not needed for either the hot path or the
gate. Keeping Rust behind a process boundary also means canon's Python test suite simply *skips* the Rust
attestation when the binary isn't built — exactly like the corpus-gated tests today.

## 3. The IR wire contract — the cross-language artifact

The thing both sides agree on. Reuse what exists: `MotifGraph._body()` is already a canonical JSON
(`{rule_id, selection:[field_match…], suppressions:[block…]}`) and is already the content-address basis. Promote
it to **the IR's wire format** with a fixed schema, so:

- **rules in:** the motif graph JSON (one rule, or an array — a ruleset).
- **events in:** source-native JSON records (one JSON object per line).
- **firings out:** per `(event, rule)` a boolean, or the list of firing rule-ids per event.

This JSON contract is itself a deliverable — it's the language-agnostic seam made concrete, and any future
emitter (Go, a GPU kernel) targets it.

## 4. The semantics profile — the hard part, and the whole point

§3 of the IR doc: structure ports, semantics don't. Rust vs Python will diverge on specific, enumerable
landmines — and surfacing them *is* the value, because today the IR's string semantics are implicit (the Python
emitter just uses its language defaults). The slice must **pin a semantics profile in the IR** so every emitter
targets the *spec*, not its language's defaults:

- **Case-folding.** Python `str.lower()` and Rust `str::to_lowercase()` are both Unicode and **agree on ASCII
  but can differ on non-ASCII** (final sigma, ß, locale). Sigma's Windows string semantics are effectively
  ASCII (paths, DLLs). **▶ Pin the match to ASCII-case-insensitive** and have both emitters do ASCII-lowercase
  explicitly. Note: this is a (tiny) change to the *Python* emitter, which currently calls full-Unicode
  `.lower()` — the first concrete artifact of this work may be a one-line correction to `sigma_eval`.
- **Substring / endswith / startswith / contains.** Python operates on code points; Rust `&str` ops on UTF-8
  respecting char boundaries — **for valid UTF-8 they agree.** Pin: inputs are valid UTF-8 (JSON guarantees it).
- **Missing field → `""`.** Both default an absent field to empty string (the Python emitter and SPARQL
  serializer already do; pin it for Rust).
- **Non-string coercion — a real divergence.** Python `str(True)` is `"True"`; Rust/serde renders `true`.
  `str(1.0)` is `"1.0"`; number formatting can differ. Most telemetry fields are strings, but **▶ the IR must
  define a canonical coercion** (e.g. compare against the raw JSON token, or a pinned bool/number→string rule)
  — the attestation will otherwise flag bools/numbers as disagreements.
- **Wildcards.** Neither handles `*` (treated literally); consistent, but pin it so a future emitter doesn't
  "helpfully" add globbing.

The deliverable here is a short **semantics spec** (one section), not just code — it's what makes "verified
translation" rigorous rather than per-language luck.

## 5. The gate — extend agreement to N emitters, on an edge-case corpus

`attest_emitter_agreement(graph, events)` currently compares Python↔SPARQL. Extend to **Python (reference
oracle) ↔ SPARQL ↔ Rust**, pairwise, with each disagreement localized to *(emitter, event, rule)*. Two
additions matter:

- **Rust runs as a subprocess in the harness:** pipe the corpus once, collect per-event firings, diff. (Batch,
  not per-event — no PyO3 needed.)
- **The corpus must include the §4 landmines.** OTRF is the happy path; it won't exercise non-ASCII, bools,
  numeric fields, empty strings, or unicode-case edges. **▶ Synthesize an adversarial edge-case corpus** — and
  this is exactly where the **dataset-generator** (`design/dataset_generator_product.md`) earns its keep:
  generate, by construction, the events that stress the semantic seam. The two designs meet here: the generator
  produces the corpus the cross-emitter gate needs.

A green N-emitter attestation on the edge-case corpus is the license to run the Rust worker in production in
place of the oracle. A red one is a *finding* — it tells you exactly which semantic the IR hadn't pinned.

## 6. Performance — what we measure, and the honest expectation

Measure, don't assert: throughput (events/sec/core) and scaling (events/sec vs cores) for **thousands of rules
× a large event batch**, Rust-interpreter vs Python, same rules, same corpus. Expected shape: Python flat and
single-core-bound; Rust higher per-core and ~linear in cores. **The headline number is throughput at ruleset
scale and parallel scaling — not a per-comparison ratio**, which would be small and misleading. If the
interpreter's dispatch turns out to bound throughput, *that* is the trigger to consider codegen (§1b) — and
only then.

## 7. Scope — in / deferred

**In (first Rust slice):**
- a Rust **interpreter** over the two existing molecules (field-match, suppression), consuming the §3 JSON;
- the §4 **semantics profile** pinned, with the Python emitter corrected to match;
- a **subprocess bridge** + N-emitter `attest_emitter_agreement`;
- an **edge-case corpus** (hand-seeded first; generator-backed when that lands);
- a **benchmark** (§6).

**Deferred (layers 2+):** codegen (§1b); PyO3 in-process binding (§2b); correlation/join molecules (multi-event
— needs windowing/state in the streaming model, materially harder); full-ruleset compile; SIMD/GPU.

## 8. Risks & honest unknowns

- **Toolchain.** Rust enters build/CI. Mitigation: the subprocess boundary keeps it decoupled; Python tests
  skip the Rust gate when the binary is absent (corpus-gated-test pattern).
- **Semantic divergence is expected, not feared** — it's the designed output of the gate. The real cost is that
  pinning the profile likely edits `sigma_eval` (full-Unicode `.lower()` → ASCII), with a re-run of the existing
  Sigma tests to confirm no regression on real rules.
- **Over-scoping.** Resist codegen and correlation molecules until measured need (the earned-not-designed rule).
- **The win might be smaller than hoped on the current corpora** (single rule, thousands of events) — the payoff
  is only visible at ruleset × big-batch scale, which we don't yet have a real workload for. The benchmark must
  use a *synthetic* large workload to even see it; until there's a real enterprise batch, the value is argued,
  not field-shown (the standing constructive-vs-operational line).

## 9. Where it lives

A **standalone Rust crate**, parted out like the dataset-generator — working name `motif-rs` (TBD). canon
(Python) is **one consumer**, via the subprocess contract. This matches the language-agnostic seam: the crate
knows the IR wire format and nothing about canon. The crate ships the interpreter + the CLI; canon ships the
bridge + the extended attestation.

## 10. Smallest first slice (when greenlit)

1. Freeze the **§3 JSON wire contract** + write the **§4 semantics spec** (one doc section); correct the Python
   emitter to the pinned ASCII-case semantics and re-run the Sigma tests.
2. `motif-rs`: a Rust interpreter for field-match + suppression reading the wire JSON + events JSONL, writing
   per-event firings. CLI only; no PyO3, no codegen.
3. Python **subprocess bridge** + extend `attest_emitter_agreement` to three emitters.
4. **Edge-case corpus** (hand-seeded) exercising the §4 landmines; attest Python↔SPARQL↔Rust green on it *and*
   on OTRF.
5. **Benchmark** (§6) on a synthetic thousands-rules × large-batch workload; record the throughput + scaling
   numbers in the guarantees ledger.

Do **not** start at codegen, PyO3, or correlation molecules. The slice proves one thing: **a native emitter
that agrees with the oracle on the adversarial corpus, and scales with cores.**

## 11. The more general endpoint — emit standards, not emitters

Step back: a per-language emitter (Python, SPARQL, Rust, Go…) is **O(targets) of hand-written backends**, and
each target re-opens the §4 equivalence problem. The genuinely future-proof move is the same discipline canon
already applies to ontologies — *don't re-mint, adopt the standard waist* (import `prov:` directly; OCSF as the
shared schema). Applied to execution: **emit a portable plan over portable data, run by a vectorized engine.**

- **Plan IR:** compile the ruleset to a **Substrait** plan (the open, cross-engine query-plan standard) — *one*
  emitter, not one per language.
- **Data:** **Arrow** columnar batches — the events as columns, which is what makes the scale lever (SIMD,
  cache-friendly scans) available at all.
- **Engine:** a vectorized columnar engine — **DataFusion** (Arrow + Rust) embedded, or DuckDB / Velox / Spark
  for distributed. So "the Rust emitter" *dissolves*: Rust is the engine you didn't write, not an interpreter
  you did.

Why this is better at scale, not just trendier:
1. **Vectorized/columnar is the real hardware lever** for billions of events; a row-at-a-time interpreter
   (Python *or* bespoke Rust) leaves it on the table.
2. **You inherit the optimizer** — common-subexpression elimination shares a predicate that a thousand rules
   all check (`TargetImage endswith \lsass.exe` computed once), reordering by selectivity, indexing — none of
   it hand-written.
3. **Hot and cold unify:** the same plan-IR expresses "fire rules over events" (hot) and "which rules cover
   T1003.001" (cold, a query over the rule table). One engine, two plans — the split stops being two systems.
4. **Portability for free:** one Substrait plan runs embedded, distributed, or in a warehouse; a new target is
   a new Substrait *consumer*, maintained by someone else.

Honest limits — this over-reaches if unbounded:
- **Field-match/suppression molecules are *perfectly* relational** (conjunctive predicates) — most of the Sigma
  hot path maps cleanly.
- **Correlation/multi-EID molecules** are windowed self-joins — engines do them, with more friction + state.
- **The statistical battery (MI, CFAR, circular stats) is *not* relational** — custom aggregations; forcing
  them into SQL is wrong. They attach as **UDF/UDAF** (the engine's extension API). So the general form is
  *layered*: a portable plan for the relational majority + a UDF escape hatch for the non-relational primitives.
- **The §4 pinning problem recurs** as "the engine's `ends_with` vs the spec" — the semantics profile and the
  cross-emitter attestation remain the license, unchanged.

**So the Rust interpreter (§§1–10) is a disposable stepping stone, named as such.** The semantics profile is the
hard part and is cheaper to pin in a ~200-line Rust interpreter than inside a query engine. **▶ Keep the
interpreter only to nail the §4 spec; treat it as throwaway; make the named production endpoint "emit
Substrait/Arrow to a vectorized engine," not the bespoke interpreter.** Cheap rung to learn the semantics;
standard waist for the real thing — the earned-not-designed discipline, one level up.
