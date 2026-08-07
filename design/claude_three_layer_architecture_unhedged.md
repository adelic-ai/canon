# Three-layer architecture (unhedged — adopt off-the-shelf, build only what's novel)

> **SUPERSEDED (2026-08-07) — kept as the tried-and-dropped record, not as current architecture.**
> The `mathabc-core` layer proposed below was never built and is not planned. mathabc is a concept
> artifact: an experiment in Python's `ABCMeta` / `Protocol` / `Generic[T]` machinery applied to the
> math containment hierarchy. Every structure in it is abstract — there is no shipped `Integers()`,
> no `F_p`, no polynomial ring; the caller supplies the concrete math. So binding canon's
> `semantic_core.protocols.Lattice` to `mathabc.order.Lattice` would trade one abstract surface for
> another and add a dependency for it. The structural Protocol is the surface, by decision.
> The rest of this document's adopt-off-the-shelf argument (D3FEND as OWL, rdflib / owlready2 /
> pySHACL, TASC dissolved into an adapter) did hold and is realized in `packages/semantic-core` and
> `packages/semantic-cyber`. The current spine is `design/self_validation_architecture.md`.

## Thesis

Don't rebuild what the W3C semantic stack already provides. Adopt D3FEND as the cyber knowledge graph. Dissolve TASC into a small adapter package. Build only what's genuinely novel: typed math (mathabc-core), feature-engineering substrate with lineage (forge-core), and the few small glue layers between them.

## What's off-the-shelf

- **D3FEND** — MITRE's defensive OWL ontology, published Jun 2021. Already has typed relationships (`d3f:provides-attack-detection`, `d3f:enables`, `d3f:produces-artifact-of-type`, `d3f:related-attack-technique`), defensive artifacts and capabilities as typed instances, built-in ATT&CK technique linkages, SPARQL-queryable, updated by MITRE. The 80% solution to "cyber concept lattice." You SPARQL-query it, you don't re-derive it.
- **ATT&CK STIX 2.1** — offensive-side concept graph, already structured.
- **OCSF JSON Schema** — typed telemetry vocabulary (per the existing `ocsf-data-shape-standard` pin).
- **Sigma manifests, CAR analytics** — loadable as graph nodes via custom adapters.
- **rdflib** — RDF/SPARQL substrate.
- **owlready2** — OWL DL reasoning via HermiT/Pellet. Real entailment, not just BT/NT walking.
- **pySHACL** — SHACL validation. The self-falsifying piece at the graph layer.
- **NetworkX** — graph algorithms.

What these together provide: a complete, maintained, more-capable replacement for everything TASC's custom SKOS inference engine recapitulates.

## What's genuinely novel and worth building

Short list:

1. **FCA implication-basis extraction** from the unified graph, output as a `mathabc.order.Lattice` instance — ~500 LOC on NetworkX.
2. **Cross-framework SKOS bridges** that aren't published anywhere (Sigma↔D3FEND, CAR↔D3FEND, OCSF↔ATT&CK at fine granularity). Real curation work; not infrastructure.
3. **`Feature.semantic: ConceptId`** linking layer in forge-core — ties feature engineering outputs to concept-lattice positions — ~500 LOC.
4. **mathabc-core** — typed abstract algebra in Python. Genuinely no off-the-shelf equivalent at this granularity (DisCoPy is closest, SageMath has it but is heavy). ~3-4k LOC trimmed from current mathabc.
5. **forge-core** — feature engineering with Surface/lattice/lineage substrate. No off-the-shelf equivalent for the composition-with-provenance pattern. ~10-11k LOC post-restructure.

Total novel construction across the stack: ~17-18k LOC. Most of which (~13-14k) is mathabc-core trim + forge-core restructure — code you mostly have. Real new code: ~3-4k LOC.

## The minimal viable stack

```
mathabc-core           # 3-4k LOC, trim of current mathabc
semantic-core          # wraps rdflib + owlready2 + pySHACL + FCA: ~1.5k LOC
forge-core             # 10-11k LOC, post-restructure
semantic-cyber         # ~800 LOC: D3FEND loader + ATT&CK STIX loader
                       # + OCSF/Sigma/CAR bridges + SHACL shapes
forge-cyber            # ~1.5k LOC: DomainSchema reads OCSF, optional
                       # ConceptId attachment from semantic-cyber
```

`semantic-core` shrinks from earlier 2-3k estimate to ~1.5k because once you delegate heavy lifting to `owlready2`/`pySHACL`/`rdflib`, you're writing Protocols + the FCA layer + glue. That's small.

`semantic-cyber` shrinks from earlier 2k to ~800 LOC because loading published OWL ontologies (D3FEND.ttl is downloadable) is an `rdflib.Graph().parse()` call + bridge definitions for the things D3FEND doesn't cover.

## Architecture

```
                        ┌─────────────────┐
                        │  mathabc-core   │  (foundation + algebra + order
                        │  ~3-4k LOC      │   + logic + categories)
                        └────────▲────────┘
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
       ┌────────┴────────┐               ┌────────┴────────┐
       │  semantic-core  │               │   forge-core    │
       │  ~1.5k LOC      │               │  ~10-11k LOC    │
       │  (wraps W3C     │               │  (Surface,      │
       │   stack +       │               │   lattice,      │
       │   FCA +         │               │   lineage,      │
       │   Protocols)    │               │   primitives)   │
       └────────▲────────┘               └────────▲────────┘
                │                                 │
   ┌────────────┼────────────┐         ┌──────────┼──────────┐
   │            │            │         │          │          │
semantic-   semantic-   semantic-   forge-      forge-     forge-
  cyber      math*        geo       cyber        eeg      wellbore
  (~800)   (provided     (later)    (~1.5k)     (later)    (later)
            by mathabc)
```

`*semantic-math` is *provided by* mathabc — mathabc plays double role as both the typed-math foundation AND its own domain ontology.

## TASC dissolves into semantic-cyber

The "TASC" project name doesn't survive. Its decomposition:

- **The 4900+ catalog nodes** → data files loaded into the rdflib graph at startup.
- **The 9 framework adapters** → bridge definitions (FrameworkAdapter Protocol implementations) between D3FEND/ATT&CK and the other frameworks (Sigma, CAR, OCSF, etc.).
- **The SKOS inference engine** → thrown out, replaced by `owlready2`+`pySHACL`. The off-the-shelf stack is more capable.
- **The catalog-curation decisions** → preserved as data and bridge definitions. Real value.
- **L0 axes that doubled as runtime-matcher state** → deleted (cyber data-shape lives in OCSF per the existing pin).

What was TASC as a project becomes `semantic-cyber/` — one domain adapter in a larger architecture. ~800 LOC of code + the migrated catalog data.

## Cost estimate (unhedged build)

| Layer | LOC | Time (focused) |
|-------|-----|----------------|
| mathabc-core trim | ~3-4k (mostly from existing) | 1-2 weeks |
| semantic-core (wrap W3C stack + FCA) | ~1.5k | 1-2 weeks |
| forge-core restructure | ~10-11k (mostly existing) | 2-3 weeks |
| semantic-cyber (adopt D3FEND + bridges + migrate TASC data) | ~800 + migrate 9.3MB data | 1 week |
| forge-cyber (port substrate-prototype) | ~1.5k | 1 week |
| forge-eeg + semantic-eeg (first non-cyber) | ~1.5k combined | 1-1.5 weeks |
| **Total** | **~17-19k LOC, ~10MB data** | **7-10 weeks focused** |

Down from the hedged estimate of 10-13 weeks. The reduction comes from:
- Adopting D3FEND instead of building cyber ontology (-2 weeks)
- Delegating to `owlready2`+`pySHACL`+`rdflib` instead of building custom inference (-1-2 weeks)

So **~2 months** as the realistic unhedged build, not 3 months.

## On the time-wasted question

Honest answer: yes, some, not catastrophic.

**Genuinely wasted:** the parts of TASC's 11.5k LOC that recapitulate W3C infrastructure. Probably 30-40% of code (~4k LOC) is doing what `owlready2`/`pySHACL`/`rdflib` do better. SKOS inference, SHACL-equivalent validation done custom, graph traversal logic that SPARQL handles natively.

**Not wasted, even though it could have been "skipped":** the framing work. `tasc_is_a_thesaurus` (library-science). `substrate_self_falsifying` (generator-validator pairs). `minimum_primitives_lattice` (FCA-derived basis). `bootstrap_construction_pipeline` (LLM as callable tool, not the system). `llm_smoothing_caught_by_tools` (measured LLM failure modes). These are real intellectual progress. Without them you wouldn't *recognize* that D3FEND has the right shape when you see it.

**The hard truth about the discovery:** D3FEND was discoverable earlier. A literature scan with the right keywords ("defensive ontology", "cyber knowledge graph", "MITRE D3FEND") would have surfaced it in an hour. You didn't do that scan because the framing that would *motivate* the scan hadn't crystallized yet. The framing work bought the discoverability; the discoverability was sitting there the whole time.

Time cost ballpark: probably 2-4 weeks of TASC implementation time would have been redirected toward integration if D3FEND had been on the radar from the start. Maybe more. The data-curation and adapter work isn't wasted at all — that's substance.

## The load-bearing decision

**Does TASC continue as a separate project name and identity, or does it dissolve into `semantic-cyber`?**

Everything else flows from that.

If TASC dissolves:
- The dev2 migration plan changes shape (TASC restructure → adopt D3FEND + write small adapter).
- Time-to-cyber-feature-detection-end-to-end probably *decreases* because the heavy lifting is delegated to `owlready2`.
- The catalog-data work survives, framed as semantic-cyber's bridge definitions.
- Total stack build is ~2 months focused, not 3.

If TASC continues:
- You're maintaining infrastructure that has free alternatives.
- The W3C-stack adoption is a TASC-internal refactor, not a re-architecture.

Recommendation: dissolve TASC.

## What dissolves, what survives, what gets dropped

**Survives:**
- mathabc's FOUNDATIONS-v2 (trimmed to mathabc-core)
- TASC's 4900+ catalog nodes + 9 framework adapters (migrated as semantic-cyber data + bridges)
- forge's Surface + lattice + lineage (becomes forge-core)
- substrate-prototype labs (become cyber-labs implementing DomainValidator)
- Lab discipline (HYPOTHESIS/manifest/run/validate/RESULT skeleton)
- All directional pins in memory (forge-vnext-architecture, tasc-role-correction, ocsf-data-shape-standard, etc.) — they describe the same target architecture; "TASC" is the name that dissolves

**Dropped:**
- TASC's custom SKOS inference engine (~4k LOC replaced by owlready2+pySHACL)
- TASC's L0 axes that were runtime-matcher state (deleted; data-shape in OCSF)
- `forge.signal._infer.py` schema-inference machinery as central path (opt-in only)
- `cli.py`, `sklearn.py`, `torch.py` from forge core (move to `forge-tools` if useful)
- adele (already deprecated), pickering/signalforge/csat (frozen/junkyard), memoria (junkyard)

**Dissolves into:**
- TASC → semantic-cyber
- substrate-prototype → cyber-labs
