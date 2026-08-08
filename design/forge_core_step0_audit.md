# forge-core step-0 audit — port / fix / drop

Audit of the pre-canon `forge` prototype (the quarry — a separate, unpublished repo) for the fresh agnostic build at `packages/forge-core/`. Produced 2026-05-28 by an automated audit pass over three subsystems in parallel. ~7.5k LOC, ~50 files. Read-only; no changes made.

## Headline findings (verified against committed decisions)

- **Horizon is GONE** — `lattice/scale_plan.py` confirms: `bin_unit` + `scales`, no Div(H)/lcm. ✓ as committed.
- **`hops` is ABSENT and the code argues against it** — `scale_plan.py:45-47` docstring calls hop YAGNI. This *contradicts* the committed decision to reintroduce hop as first-class lattice-aligned. Fix the stance, add `hop`.
- **`CyclicSignal` DOES NOT EXIST** (grep: zero hits). Only `RealSignal`/`ComplexSignal` under `LatticeSignal`. The three-sibling model is two-thirds built; the angular leaf is the single biggest gap.
- **Phase-laundering bug is LIVE** — `signal/_signal.py:143-150` `to_real("phase")` returns a **RealSignal** of angles; `ops/hilbert.py:113` actively recommends it. Any downstream mean/var/gradient is wrong at the ±π branch cut. Delete this path; give phase a `CyclicSignal` home with circular stats.
- **`input_kind` is declared on every Op but enforced NOWHERE** (`graph/_core.py:181` default None, never read). Type-gating today is ad-hoc `dtype.kind=="c"` checks inside `apply()`. forge-core must make the leaf type / `input_kind` load-bearing.
- **Artifact lineage works and is the keeper** — `graph/_core.py:50-87`: Artifact id = SHA256 of `op_name` + ordered `parent_ids` + `kwargs_signature`. Content-addressed by *how it was made*. Port verbatim.

## Three stale weakness-list items CORRECTED by the audit
1. **"Pipeline constraint-resolution pending — define out"** → already ABSENT. Grep finds no constraint/reconcile/global-plan in `graph/` or `chain.py`; `_core.py:31` already states "each Op carries its own plan; mismatches raise at execution." Nothing to remove. ✓ already as desired.
2. **"`detection_features`→`salient_features` rename"** → the symbol DOES NOT EXIST in the quarry (grep: zero). No cyber-leaning op names; "detection" strings are all signal-detection (period/cadence). Rename is a no-op here — the target, if any, lives in TASC/assemble contracts, not forge.
3. **"Schema inference shipped as core (`infer_axes`)"** → NOT on any default path. `signal/_infer.py::infer_axes` is called only by its test. It IS cyber-leaning (docstring: "security telemetry", "so TASC can validate", adapted from pickering/fpass; depends on `_l0_axes`). So the action is RELOCATE to forge-cyber's boundary, not "make opt-in" (already is).

## grain / bin / hop / window — confirmed the bug-prone area (the real bugs)
1. **Silent `w // cbin` integer floor** — `_measure.py:196`, mirrored `_surface_information.py:120,185,258,358`. ScalePlan never enforces `w % bin_unit == 0` (`scale_plan.py:57-60` checks only positivity). Scale 90 with bin_unit 60 silently becomes a 1-bin window. **Fix: enforce divisibility in `ScalePlan.__post_init__`, or store scales already in bin-units.** (The docstring at `scale_plan.py:29-30` says "s × bin_unit" but code consumes `w // bin_unit` — docstring and code disagree about what `scales` means. Root of this bug.)
2. **Trailing-fragment silent drop** — `_measure.py:125` (`n_bins = span // cbin`), `_surface_information.py:39`. Final partial bin discarded with no flag. Decide+document drop-vs-partial.
3. **Binning-origin DISAGREEMENT between the two kernels (representation-level-slip, LIVE in code)** — `_measure.py:134,139` floors bins from `index[0]`; `_surface_information.py:49,53` floors from absolute zero then shifts by `min`. When `index[0] % cbin != 0` the same events land in different bins → `measure_signal` and `entropy_surface` silently misalign their time axes for identical input. Both docstrings claim the same convention; one is wrong. **Fix: a single shared binning helper used by both.** This is the most dangerous correctness bug.
4. **`assemble.py:308,318` silently truncates complex→real** (`dtype=np.float64` drops `.imag`). Preserve dtype or reject mixed channels.
5. **`_surface_information.py` KL/IG drop to naive O(window) Python loops** (L259, L359) while entropy/MI are cumsum-vectorized — perf + divergence risk. Unify on the cumsum path.

Note: the cumsum window-indexing in `_measure.py` itself is CORRECT (right-aligned trailing windows, verified). No windowed-Shannon-entropy op exists in the catalog → the `H=log2(S)−T/S` identity has no current target (a gap to fill, not a bug). MSEOp's O(n²) is intrinsic SampEn (Richman-Moorman), not a fixable naive recompute.

## Consolidated port / fix / drop

**PORT (clean):** `signal/_complex.py`, `signal/_record.py` (Record is correctly lean `__slots__`, not Pydantic ✓), `signal/_information.py`, `signal/_robust.py` (Weiszfeld+Vardi-Zhang, correct ℂ), `lattice/neighborhood.py`, `lattice/flipflop.py`, `graph/_core.py` (keystone), `ops/_results.py`, `ops/_enrich.py`, `ops/spectral.py` (field-closed exemplar), `ops/hilbert.py` (the type-gating exemplar — explicit complex rejection), `ops/correlation.py`, `discovery/__init__.py`, `sklearn.py` (load-bearing thin adapter), `torch.py` (thinner — keep `as_tensor`/`ForgeDataset`, cut `as_tensor_2d`).

**FIX:**
- `signal/_signal.py` — strip complex-derived methods off the base ABC; **kill `to_real("phase")`→RealSignal**.
- `signal/_measure.py` — binning bugs (#1,#2) + narrow type to RealSignal.
- `signal/_surface.py` — `values` returns "first dict entry by insertion order" (`:172`) footgun; make primary array explicit.
- `signal/_surface_information.py` — binning-origin disagreement (#3), vectorize KL/IG, narrow type.
- `lattice/scale_plan.py` — **add `hop`**, enforce `scale % bin_unit == 0`, reconcile scales representation.
- `lattice/arith.py` — drop horizon-era `smallest_divisor_gte`/`lattice_members` (+ their exports); port the rest.
- `ops/measure.py`, `ops/baselines.py`, `ops/residuals.py` — real-only gating on linear aggregations (cyclic data must be rejected or circular-pathed); `input_kind` unenforced.
- `ops/information.py` (MSEOp) — minor: gate angular data out; enforce input_kind.
- `ops/assemble.py` — complex-truncation bug (#4).
- `chain.py` — sever `forge.domains.timeseries/wellbore` imports in `load_csv` (inject ingest/DomainCorpus).
- `forge/__init__.py` — drop `domains` import + `__all__` entry.
- `cli.py` — sever `forge.domains` refs in `_cmd_measure`/`_cmd_info`; rest portable.
- `_workspace.py` — DEFER (agnostic but unwired, no consumer).

**DROP:** `signal/_l0_axes.py` (cyber L0 → OCSF via forge-cyber), `signal/_infer.py` (relocate to forge-cyber boundary; cyber-leaning + depends on _l0_axes), `graph/_ops.py` (empty stub), `analysis.py` (empty stub), `ops/{alignment,changepoint,filters,projection,wavelets}.py` (all empty stubs — reimplement fresh when needed; changepoint=IT, filters/wavelets=DSP, alignment/projection=general).

**EJECT-TO-SIBLING:** `domains/*` — coupling is shallow + one-directional (domains import 4 signal types from core; core touches domains in only 4 lazy sites). `timeseries.py` (166 LOC, the DomainCorpus/DomainSchema template) → forge-timeseries/example; `wellbore.py` (176 LOC, richest — group_by/CATEGORICAL path) → forge-wellbore; `eeg.py` (**EMPTY — priority-1 consumer is 0 LOC, build from scratch**), `equities.py`/`intermagnet.py` (empty intent-stubs).

## Implicit boundaries to formalize as the three Protocols
- **DomainCorpus** — implicit as `ingest_csv()/from_values()/from_log()` free functions in timeseries/wellbore returning `list[Record]`. `manifest()` is net-new.
- **DomainSchema** — implicit in `schema_for()` + module-level `ValueSchema(...)` constructions, and most strongly in `infer_axes` (a literal field→type map). Make `infer_axes` the opt-in boundary impl in forge-cyber.
- **DomainValidator** — NO implicit version anywhere. Net-new. (Substrate-prototype labs become its first implementers.)

## Sequenced next actions (step-1 onward)
1. Scaffold workspace member; bring over the PORT-clean set first (they compile without the rest).
2. Define `CyclicSignal` (in `_complex.py` beside the other leaves) + circular-stat aggregations BEFORE porting measure/baselines/residuals — those FIXes depend on it.
3. Single shared binning helper (kills bug #3) + `ScalePlan` divisibility enforcement + `hop` field (kills #1, adds the committed feature) — do these together; they're the same structure.
4. Then ops, with `input_kind`/leaf-type gating made load-bearing.
5. Protocols (DomainCorpus/Schema/Validator) — lock signatures; resolve the SOONER-THAN-LATER DomainValidator signature + EDA-composition question first.
