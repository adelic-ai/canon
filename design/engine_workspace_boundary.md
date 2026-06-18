# The engine / workspace boundary — canon is the instrument, the data is the case file

**Status: design, 2026-06-18. Design-only.** Formalizes a separation that is already half-realized: the data
particular to a set/task lives *outside* canon. canon is the domain-agnostic engine; a per-engagement
**workspace** holds the data and everything derived from it. Records the principle, the three tiers, the
already-true parts, the honest exceptions, and the one missing abstraction (the workspace manifest).

## 0. The principle

A statement and the data it is about are different kinds of thing. canon's verdicts, attestations, baselines,
and coverage maps are *about* a particular set of logs for a particular task — they are not properties of the
engine. So **the engine is universal and shippable; the data and everything derived from it is particular and
swappable.** Mixing them makes canon un-shippable (it carries one enterprise's logs), un-multi-tenant (one
data set baked in), and dishonest about reuse (engine and case-findings versioned as one thing). The fix is a
clean cut: canon = instrument, the workspace = case file.

## 1. Already half-true (the tell that it's the right cut)

The raw corpora are *already* outside canon. Tests reference `~/data/otrf-…` by path and **skip if absent**
(`pytest.mark.skipif(not OTRF.exists())`); nothing in the repo vendors telemetry. The instinct is correct and
partly built — this doc makes the cut deliberate and extends it from the *raw* data to the *derived* data,
which is the part still entangled.

## 2. Three tiers, not two

- **Engine — canon proper (universal, shippable).** The substrate (provenance / carrier / guarantee /
  custody), the detector families, the motif IR + emitters, the fidelity machinery, the contracts, and — the
  load-bearing inclusion — the *learning algorithm*. This is the instrument; it knows nothing about any
  particular data set.
- **Shared reference knowledge (universal-ish, external, currently partly vendored).** ATT&CK / D3FEND / OCSF /
  the SigmaHQ corpus. Not engagement-specific, but still external data the engine *consumes*. Some is vendored
  today (`semantic-cyber/data/sigma-rules`). See §5 — this is a real, open vendored-vs-referenced decision.
- **Engagement-particular — the workspace (outside, per-engagement, swappable).** *This* enterprise's telemetry
  refs, the ruleset pin, the derived verdicts and fidelity attestations, the accumulated baselines / priors /
  regime-ledger, the retention coverage map, and recipe CIDs. The "growing knowledge about that full set" lives
  here — never in canon.

## 3. The sharp distinction — algorithm in canon, learned parameters in the workspace

The cut that makes tier 1 vs tier 3 unambiguous is the same one ML draws between **model code and model
weights.** The learning *algorithm* (how a per-entity baseline is fit, how a regime is detected, how a dispatch
prior is updated) is engine — it ships with canon. What it *learned* (the actual baselines, the regime ledger,
the priors for this enterprise) is particular to the set, so it is **case data and lives in the workspace.**

This places the earlier loop precisely: "auto-ML it back into the sauce" and "re-go-over with new knowledge" —
the *sauce* is the workspace. canon supplies the algorithm; the workspace holds and accumulates the parameters.
A re-run is the algorithm (engine, fixed) over the data + prior parameters (workspace, growing).

## 4. What a workspace is (its layout)

A workspace is the unit of "a run of canon over a data set for a task." Concretely a directory / store holding:

- **source refs** — pointers (path / URI / CID) to the corpora, *not* the bytes unless small; with each
  source's retention window (→ the §-fragmentation coverage staircase).
- **the ruleset pin** — which rule corpus + version/CID the detections were evaluated against.
- **derived artifacts** — verdicts (with their provenance DAGs), fidelity attestations, the coverage map for
  this retention, the location-coverage records.
- **learned parameters** — the accumulated baselines / priors / regime-ledger (§3).
- **recipes** — for any synthetic data mixed in, the dataset-generator recipe CIDs (reproducible).

Because everything is content-addressed, a workspace is **self-describing and reproducible**, and a re-run can
**diff against the prior workspace state** — exactly which verdicts flipped, explained by the new input node
(new data, new rule, new parameter). The workspace *is* the durable, auditable record of an engagement.

## 5. Honest caveats — where the cut should not go

- **Tiny deterministic test fixtures stay in canon.** Small synthetic events that pin engine behavior in unit
  tests are code-adjacent, not engagement data. The line is *load-bearing on a result* (→ workspace) vs
  *pins engine behavior* (→ stays). The OTRF skip-if-absent pattern is the model for "real data is external."
- **The vendored SigmaHQ corpus is a genuine open decision.** Vendoring gives reproducible tests; the
  "mint-don't-vendor, version-in-provenance" lesson (KINAITICS) argues for referencing by version+CID. Tier 2
  can resolve either way; flag it, don't force it in this note.
- **Don't over-abstract early.** The workspace is a manifest + a store, not a framework. Build the manifest when
  a second data set or a re-run actually needs it — the same earned-not-designed discipline.

## 6. The one missing abstraction — the workspace manifest

The seam already exists: the registry's detectors take corpus *paths*, and `run_applicable(corpus)` is "fire
the applicable detectors over this input." What's missing is a first-class object binding the parts:

```
Workspace = {
  sources:    [{ ref, kind, retention_window, cid? }, …],
  ruleset:    { corpus_ref, version_or_cid },
  derived:    <store for verdicts / attestations / coverage map>,
  parameters: <store for baselines / priors / regime-ledger>,
  recipes:    [<dataset-generator recipe CID>, …],
}
```

canon **points at** a workspace (reads sources + ruleset + prior parameters) and **writes back into** it
(verdicts, attestations, updated parameters). One canon, many workspaces → multi-tenant / multi-engagement by
construction. The manifest is the contract; the path-based loaders are the current, thinner form of it.

## 7. The symmetry — data in and data out are both outside

Data going *in* (the engagement workspace) and data being *produced* (the dataset-generator, already scoped as
a standalone product) are **both outside canon**; the engine sits in the middle knowing about neither. That is
the domain-agnostic-validator thesis made concrete: `provenance` is already standalone, forge-core is one
consumer, and now the data — real and synthetic — is external on both sides. canon is the validator; the data
is the world it is pointed at.

## 8. Honest scope — what this is not

- Not a storage/format decision (Parquet vs JSONL vs a DB) — that is a workspace-store implementation detail;
  this note fixes the *boundary*, not the bytes.
- Not multi-tenancy infrastructure — it *enables* it (one engine, many workspaces) but ships none.
- Not a change to the engine's code today — it is the principle that constrains where derived artifacts are
  written next, and the spec for the manifest when it is built.

## 9. Smallest first slice (when greenlit)

1. A `Workspace` manifest dataclass (§6) + load/save — sources, ruleset pin, and two stores (derived,
   parameters). No new formats; reuse the existing verdict store + content-addressing.
2. Make one existing flow (e.g. `lsass_location_coverage`) read its corpus + ruleset *from a workspace* and
   write its verdict + attestations *into the workspace's derived store*, instead of taking a bare path.
3. A second workspace (a different corpus) proves swappability + that the engine carries no set-specific state.
4. A re-run over the same workspace with a changed ruleset pin, diffed against the prior derived store — the
   re-analysis story (§4) made concrete.

Do **not** build the storage engine, multi-tenant infra, or the parameter-learning store first — the slice
proves one thing: **the engine runs against a swappable workspace and writes its findings back, with no
set-specific state left inside canon.**
