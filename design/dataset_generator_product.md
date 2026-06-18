# Cyber Dataset Generator — a standalone product (design)

**Status: product design, 2026-06-18. Design-only; no code yet.** A *standalone* product — its eventual home
is its own repo/package (working name `cyberforge` / `synthcyber` — TBD), not inside canon. canon is **one
consumer**, not the owner. This doc is step 1; read and react before any build.

## 1. What it is, and the gap it fills

A **composable generator + library for labeled, synthetic cyber datasets.** It assembles telemetry corpora
(host / network / cloud / auth events) in which **every event's ground truth is known by construction** —
because the generator placed it. You dial the technique, the instance count, the difficulty, the drift, the
noise; out comes a corpus + its labels + a reproducible recipe.

The gap: **labeled cyber data is scarce, expensive, and uncertain.** Real corpora are unlabeled or
weakly-labeled (you *infer* what's malicious); public labeled sets are few, static, and not parameterizable.
So you cannot cheaply ask "give me 200 kerberoasting instances at signal-to-noise X, with calibration drift Y,
mixed with a non-Rubeus tool variant" — which is *exactly* what's needed to test detection machinery, train/eval
ML, and exercise things like fidelity-weighting and the exchangeability monitor at controlled difficulty.

## 2. The core model — pieces → scenarios → composition → labeled corpus

Three layers, each composable:

- **Pieces** (the library) — parameterized *event templates*: a Sysmon EID10 lsass read, a 4769 RC4 TGS
  request, a CloudTrail `RunInstances`, an EID4611 logon-provider registration. Atomic, typed, reusable. The
  library *accretes* pieces, indexed by the technique/artifact they instantiate (sampled "from anything we
  know" — ATT&CK-tagged).
- **Scenarios** (mechanisms) — a labeled attack pattern that emits a *set* of pieces with ground-truth labels:
  *kerberoasting* = N distinct RC4 TGS requests from one account; *comsvcs dump* = spawn + GUID-joined read;
  *beacon coordination* = synchronized multi-host schedule. A scenario knows its technique, its actor-role
  assignments, and which events are the malicious ground truth.
- **Composition** — assemble scenarios + **background/noise** (the normal population the anomaly is relative
  to) + optional **chains** (multi-technique campaigns through the kill-chain state space) into a corpus, with
  global knobs (below).

A generated dataset = `{events[], labels[], recipe}` where labels are per-event ground truth (technique,
actor-role, benign/malicious) and `recipe` is the full parameterization.

## 3. Labels are correct-by-construction — the core value

The generator *placed* every malicious event, so it *knows* the ground truth with certainty. This is the one
thing real data can't give cheaply and the reason the product exists: **labels you don't have to trust** —
they're definitional, not inferred. (Corollary, from canon's fidelity work: because the labels are exact, you
can *audit detectors against them* AND, run the other way, audit *suspect labels* against trusted detectors.)

## 4. Difficulty / correctness knobs (the "different levels" you want)

Global parameters that make the same scenario easy or hard, valid or adversarial:
- **signal strength** — how separable the malicious is from noise (fan-out breadth, rarity, coordination
  tightness).
- **drift / stationarity** — stationary vs. concept-drifting background (directly exercises the exchangeability
  monitor's `bounded`-vs-demote decision).
- **noise level / population size** — the standing baseline's size and variance.
- **evasion variants** — tool-specific artifact vs. behavioral-only (e.g. Rubeus-with-4611 vs. Impacket-no-4611)
  — to exercise corroboration *independence* and the tool-vs-behavior split.
- **multi-technique chains** — a campaign trajectory through tactics (to exercise the kill-chain / HMM).
- **adversarial / edge cases** — boundary-of-tolerance manipulations (round-off-near-threshold, reordering) to
  test the machinery's *correctness*, not just its accuracy.

These let one ask for a corpus at a precise point in (difficulty × correctness × realism) space.

## 5. Output schema — source-native and/or normalized

Emit in either:
- **source-native** (Sysmon JSONL, faker-Kerberos CSV, CloudTrail JSON) — matches existing loaders, lowest
  friction for testing canon's detectors as-is; or
- **normalized** (OCSF / the W-coordinate shape) — cross-source comparable, the data-side vocabulary.
Multi-modal by construction (host / network / cloud / auth share the corpus). The schema is a *render target*,
not the model — the internal representation is the typed event + labels; serializers project to each schema.

## 6. Provenance + catalog — reproducible, content-addressed, git-versioned

Every dataset carries its own provenance (canon's discipline, applied to the data itself):
- the **recipe** (scenarios, knobs, seed) is recorded and **content-addressed** (a recipe CID);
- re-running a recipe (same seed) **re-derives the identical corpus** → datasets are *reproducible artifacts*,
  not opaque blobs;
- the **catalog** marks each dataset by `{recipe-CID, labels-summary, knob-vector, schema}` and is **git-backed**
  (your "store/mark + just use git"). A dataset is referenced by CID; the bytes live in git/LFS or a store.

So a dataset is auditable and citable: "trained/evaluated on corpus `cid:…`, recipe `cid:…`" — the same
justified-artifact honesty canon gives verdicts, given to data.

## 7. LLM role — bounded proposer, never the source

An LLM may *propose* pieces or scenarios (draft a new event template, suggest a variant, paraphrase a
technique into a mechanism). It is **not** the data source: the generator is the deterministic, labeled,
correct-by-construction substrate; the LLM's drafts are *reviewed and made deterministic* before they generate
data. Same proposer-vs-verifier split as everywhere — LLM proposes pieces; the generator produces labeled data.

## 8. Interface

- **library** — compose generators in code: `corpus = compose([kerberoast(instances=50, drift=0.3), noise(n=400)])`.
- **CLI** — `gen kerberoast --instances 50 --drift 0.3 --schema sysmon --out corpus.json` → writes the corpus +
  the recipe + registers it in the catalog by CID.
- **catalog** — `ls` / `get <cid>` / `recipe <cid>` over the git-backed store.

## 9. Relationship to canon — one consumer, and the seeds already exist

canon already has the first **scenarios** in proper: `synthesize_kerberoast_corpus` and
`synthesize_coordination_events`. The product is, in part, *extracting and generalizing* those into a standalone
composable library. canon then consumes generated corpora to: exercise the **fidelity-weighting** step (a
many-detector × many-instance labeled case — the thing real corpora only half-cover), validate detectors,
drive the exchangeability monitor with controlled drift, and audit its own labels. The dependency points
**canon → generator**, never the reverse (the generator knows nothing about canon).

## 10. Honest scope — what it is *not*

Synthetic ≠ real. A generated corpus validates **mechanism** (does the machinery do the right thing on a
*known* signal) and supports **training / controlled experiments / CI fixtures** — it is **not** operational
field validation. canon already keeps this line (constructive existence-proof ≠ operational validation); the
product inherits it: a dataset's realism is a *knob and a recorded claim*, never an assertion that results
transfer to the wild. Over-fitting machinery to synthetic quirks is the risk to guard (mitigate: vary recipes,
hold out, and cross-check against the few real corpora).

## 11. Smallest first slice (when build is greenlit)

1. Extract `synthesize_kerberoast_corpus` + `synthesize_coordination_events` into a `scenarios/` module with a
   typed `(events, labels, recipe)` return.
2. A `compose()` + a `noise()` background + the 3 core knobs (instances, signal strength, drift).
3. Source-native Sysmon/Kerberos serializers (match existing loaders).
4. CID-recipe + a flat git-backed catalog.
5. Validate by regenerating the *found* labeled multi-detector case (comsvcs-style) at N instances and running
   canon's fidelity-weighting against it.

Do **not** build the OCSF serializer, the LLM proposer, or the full knob-space first — those are layers 2+.
