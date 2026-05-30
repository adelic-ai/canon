# Canon self-validation architecture — the kigumi blueprint

**Status:** design, 2026-05-30. The shared spine for both realization versions
(`self_validation_v1_python_extend.md`, `self_validation_v2_first_principles.md`).
Grounded in a four-front prior-art survey (provenance/custody, dataflow-DAG,
verification, cross-cutting folds) — see the *Borrow ledger* for what is taken
from where and the *Wheel-vs-novel ledger* for what is genuinely canon's.

## 0. Purpose (the north star this answers to)

Exploit code to its fullest potential: a system where **no result is asserted that
isn't justified back to its inputs and shown on demand** — forensic-grade, down to
chain of custody of the log from its point of entry. The deliberate inversion of
how AI is perceived today (fluent, confident, unjustified). This is a research and
learning artifact, not an adoption play; it must stand as an object of thought on
its own *and* actually work — working is necessary, not sufficient.

## 1. The one structural idea

> **Every cross-cutting concern is a `≤_k`-monotone fold from one content-addressed
> computation DAG into a partially-ordered carrier (a Belnap bilattice).**

That single sentence is the joinery. It has three consequences that make the whole
stand by mutual fit rather than fasteners:

1. **They compose because they share a shape.** Value, provenance, custody,
   validation, guarantee, confidence, temporal matching, partiality — each is a
   homomorphism over the same DAG into a poset. Homomorphisms over a fixed
   structure are independent: each reads the node set and its own carrier, nothing
   else.
2. **The acceptance test is a theorem, not a vibe.** "Add concern N without touching
   concern M" is exactly *`≤_k`-monotonicity of each fold*. It is CI-checkable: each
   fold ships a property test that feeds `None`/`Both` and asserts no knowledge-order
   violation. A fold that can't be written monotone is rejected and re-cut.
3. **Justification is not metadata.** Because provenance, custody, validation, and
   guarantee are *folds of the authoritative structure* (not side-logs), the
   justification of a result *is the same object* as the result. That is the part no
   prior system does.

## 2. The master joint — content-addressed DAG (a named wheel)

Computation is a lazy DAG of **Entities** (value-positions) and **Activities**
(op-firings). This is **not novel and must not be defended as such**; naming it
correctly inherits decades of proofs:

- It is a **Merkle DAG / IPLD CID**: a node id is the hash of its contents and its
  children's ids. "Identical sub-DAGs share an id → free dedup" is the *defining
  property* of Merkle DAGs, not an invention. (Also independently Unison's AST-hash
  addressing, Nix's constructive traces.)
- It sits at a known point in **Build Systems à la Carte** (Mokhov/Mitchell/Peyton
  Jones): an **Applicative task** (static dependencies — `parent-ids` fixed at
  construction) with **constructive traces** (content-addressed outputs) under a
  **suspending scheduler** (lazy demand-driven fold). State this in the design and
  you inherit its correctness results.
- "Lazy graph, value is one fold" is Dask `delayed` / Spark Catalyst / free-monad
  interpretation. Name the interpreter set as a free-monad/tagless-final fold
  protocol so new folds are visibly additive.

**Borrow, don't hardcode — node identity is a CID.** A **CID (Content IDentifier**,
from IPLD/IPFS) is not a bare hash but a *self-describing* content address:
`[version][multicodec: how to interpret the content][multihash: which hash function +
digest length + the digest bytes]`. "Content-addressed" = the id is derived from the
content itself, so identical content yields an identical CID and the id *verifies
integrity* (re-hash and compare). The self-describing part is the point: because the
CID carries *which* hash function produced it, the algorithm can be migrated (when
`sha256` weakens) without breaking the addressing scheme. Hardcoding `sha256` bakes the
algorithm into the protocol forever; a CID does not.

### The one-hash-three-roles seam (canon-novel)

A node's content-address is simultaneously:

```
  Merkle node id   (dedup / structural sharing)
= prov:Entity IRI  (computation provenance — "how was it produced")
= in-toto subject/product digest  (custody — "were the bytes tampered between hops")
```

No standard binds a fine-grained PROV computation DAG to an in-toto digest-custody
chain. The construct **"an Entity that is also an in-toto `product` — signed,
digest-addressed, custody-tracked — and the root `prov:Entity` of the computation"**
is the literal join between *chain of custody of the log into the system* and
*justification of the result computed from it*. It is canon's to define, and it is
the keystone of the whole arch.

### Core vs periphery — the narrow-waist seam (what's swappable, what isn't)

The CID is also the **polyglot seam**. Because a CID is derived from data over a
canonical serialization (not from any language's object identity), *any* implementation
in *any* language that hashes the same canonical bytes computes the same CID and sees
the same node — Unison's interop property. A component plugs in iff it (a) consumes a
node / the DAG by its serialization and (b) emits an artifact *addressed to that CID* in
a standard format; it never needs to share a language with anything else. This is a
**narrow-waist** ("thin-waist") architecture — the Internet's IP hourglass, WASM, LSP,
in-toto attestations all work this way: define *one* stable interchange (here:
CID-addressed nodes + a handful of standard artifact formats — PROV-O RDF, in-toto/DSSE
JSON, SHACL, guarantee certificates), and everything above and below it is implemented
independently and may vary freely. Canon's CID-addressed node *is* its narrow waist; the
contribution is *which* waist (a content-addressed self-validating computation node) and
that the same waist serves as identity, provenance, custody, and swap-seam at once.

The boundary between fixed-language and swappable is sharp, and it's drawn by one test:

> **Does the component walk the *live* DAG node-by-node with the carrier, or does it
> consume-a-node-and-emit-a-standalone-artifact?**

- **Core (one language, moves as a unit):** the tight folds over the live in-memory DAG
  that need the Belnap carrier — `evaluate`, `confidence` (LLR over the AND/OR DAG),
  `temporal` recognition, `partiality` lifting, `lineage`. Serializing per node in an
  inner loop is prohibitive, so they want one runtime. **This is the only part the
  host-language choice commits.**
- **Periphery (any language, swappable plug-ins):** components that take a node by CID /
  the serialized graph and emit a standalone hashed artifact, offline or per-result —
  custody signing (in-toto/DSSE), the machine-checked numeric proof (Coq/F\*/Gappa *off*
  the executable path, certificate addressed by the kernel's CID), PROV-O export, SHACL
  validation, conformal calibration. Each is independently replaceable and independently
  a different language.

The seam is **clean but not free**: you pay serialization at the boundary, which is
exactly why the boundary falls at "offline / per-result" rather than "inner-loop fold."

Consequence for the host-language decision (V2): it locks **only the core**. A Python
core can carry an F\*-verified-C numeric joint and a Go custody tap *today*, because those
speak wire+hash, not Python. So "Python core + polyglot joints" is the architecture
working as designed, not a compromise — and the core language can be decided **late** and
swapped against the prototype as reference, because no peripheral joint imports it. The
host-language fork therefore governs a smaller, later, lower-regret decision than it first
appears: what the core is written in, and when.

### Contracts first — the base everything else falls out of

The first build artifact is **not code — it's the contract set**: the CID format, the
artifact schemas (PROV-O shape, in-toto/DSSE envelope, `GuaranteeCertificate` schema,
SHACL shapes), and the fold-protocol signatures. These are language-independent and
outlive every implementation; a wrong implementation is cheap to redo, a wrong contract
is expensive (everything bolted to it moves). **Pluggability and the swap-seams fall out
of the contracts** — but the fold *internals* (the confidence math, the temporal
recognizer, the Belnap algebra) are real work the contract only bounds the *shape* of, not
the content. Cut the contracts first: the skeleton and the seams come free; the muscle is
still built.

### Placeholders — reference implementation vs recorded absence

A missing joint is **never a silent blank**; the form of the placeholder depends on the
joint's kind, and both are honest by construction:

- **Executable joints** (folds, detectors): the Python implementation is the
  **reference** — the correct-but-slow oracle. A faster or other-language version is
  validated against it by **diffing CID-addressed outputs** (same input → same output CID
  ⇒ faithful; translation/differential validation, free from content-addressing). Python
  holds the place *and* remains the oracle every optimized version is checked against.
- **Guarantee/artifact joints** (machine-checked proof, custody signature): a missing
  implementation is a **recorded absence**, not a stub. No proof ⇒ the certificate says
  `machine_checked: absent` and the result's tier is capped; no custody signer ⇒ custody
  is `None` (Belnap unknown), propagated honestly. The substrate applies *"no data ≠
  data-says-fine"* to its own completeness — a missing component cannot read as "fine."

### Tiered, escalating dispatch — material and rigor per subtask

Joints are selected per subtask across **two axes**, dispatched through the CID seam: a
*material/speed* axis (Python reference → Rust hot path) and a *rigor* axis (well-formed →
bounded/conformal → machine-checked). The model is **tiered compilation** (a VM interprets
first, then JIT-compiles the hot paths): run the Python reference by default, **escalate** a
subtask to a faster material when it is hot, or a more-rigorous one when it is high-stakes.
The escalation triggers fall out of the design already present: a hot path escalates on the
speed axis; a Belnap **`Both`** (two detectors confidently disagree) escalates on the rigor
axis to a verified/deeper joint to resolve the contradiction — so `Both` is both a soundness
alarm *and* an escalation signal.

### The seam is recursive — nesting and the transparency knob

Content addressing is granularity-agnostic (the Merkle property), so the swap-seam **nests**:
a joint (e.g. a Rust detector) is one node *from outside* and a sub-DAG of CID-addressed
nodes *from inside*, whose sub-components are themselves swappable joints — possibly in other
languages (a Rust detector calling a verified-C accumulation kernel and a Python conformal
calibration). The **hierarchy of subtasks = the hierarchy of nested seams = the hierarchy of
material choices**; the tiered dispatch above is this recursion as policy, this recursion is
that dispatch as structure. Bounded by the same **clean-but-not-free** rule at every level:
nest a seam where the sub-task is coarse enough to amortize serialization; keep truly tight
inner loops monolithic in the host.

This exposes one design knob per component: **black-box node vs transparent sub-DAG.**
- *Black box* — the component is one node; trust/validate its CID-addressed output (diff vs
  the reference). Internals opaque ⇒ **justification stops at its boundary.**
- *Transparent sub-DAG* — its internal steps are CID-addressed nodes, so the
  provenance/guarantee/justification folds reach *inside* it. Full forensic depth, more
  serialization cost.

The knob is a **forensic-depth-vs-performance** dial: go transparent where correctness is
load-bearing for a detection (justification must reach in), black-box where performance
dominates and reference-diff validation suffices.

## 3. The fold family

Each row is an independent `≤_k`-monotone interpreter over the DAG. "HAVE" = built
(Phases 0–4). Carrier is Belnap-lifted (§5) for every fold.

- **value** — `evaluate`; topological fold to the concrete result. HAVE.
- **provenance** — `to_prov` → PROV-O RDF (Entity/Activity/used/wasGeneratedBy/
  qualifiedAssociation→Plan). HAVE. *Borrow: W3C PROV-O directly; annotate
  derivation edges (confidence, validator verdict, timestamp) with RDF 1.2 triple
  terms, isolated behind the fold so a Basic-only export still works.*
- **custody** — in-toto Statement + DSSE envelope at the ingest boundary; each
  ingest/normalize hop is an in-toto *step* (`materials`→`products`); evaluation is
  the terminal step whose `subject` digest must equal the ingest `product` digest.
  NEW. *Borrow: in-toto/DSSE for the digest-custody chain; CASE/UCO `ProvenanceRecord`
  + custody-action terms as **vocabulary only** (speak the forensic register, don't
  immigrate the forensic world-model); W3C Verifiable Credentials for signed
  who/what-touched-it claims at entry.* Keep in-toto at the boundary (it treats steps
  as black boxes); keep PROV inside the computation.
- **well-formedness** — `validate` → SHACL over the materialized graph. HAVE.
  *Mechanism borrowed (pySHACL); the validator-per-derivation discipline is canon's.*
- **guarantee** — the fourth fold (§4): a content-addressed `GuaranteeCertificate`
  per node, tier-tagged and **demotable per result**. NEW.
- **confidence** — Chair–Varshney optimal LLR fusion in log-odds space, realized as
  a **probabilistic circuit** (OR≈sum, AND≈product). *Optimal because the detectors
  are radar/CFAR-derived with genuinely known operating points (Pfa/Pd) — the
  Bayes-optimal combiner is a closed form, not a convenient approximation.* Don't
  use Dempster's rule as the backbone (non-associative under conflict → breaks the
  fold property); keep its explicit-ignorance idea for §5 only.
- **temporal** — CEP/chronicle pattern algebra for discrete ordering/causality
  (relaxed contiguity, windows, negation) + STL quantitative robustness for the
  real-valued within-tolerance sub-conditions (beacon period ±10%, CFAR margin).
  *Chronicle recognition is the IDS-validated borrow for multi-step attack
  correlation; timed automata are the verification backstop, not the authoring
  surface; event-time + watermarks are mandatory.* The detect/validate duality
  (∃-path detect vs ∀-path validate over one pattern-DAG) is canon's.
- **cost** — resource fold (future; the design-doc Phase 6 line). Same shape.

## 4. Guarantee tiers — honest by category

The load-bearing finding: **you cannot prove "Pfa ≤ α" — it is a statement about the
input distribution, not a program-correctness property.** No proof assistant changes
this. So guarantees are tiered, and a result earns its tier from what *actually held*
on its inputs:

- **machine-checked** — the *deterministic skeleton only*: algebraic identity
  (Goertzel recurrence ≡ single-bin DFT), threshold monotonicity, and IEEE-754
  **round-off bounds** ("computed statistic within ε of exact real"). *Borrow:
  Coq/Rocq + Flocq + Gappa (round-off certificates) or F\*→C extraction (HACL\*-style,
  executable = proof). 2025 Floating-Point Accumulation Networks work fits the
  accumulation kernels: Welch averaging, CUSUM sum, Goertzel recurrence.* **Not
  reachable in pure Python on the numpy hot kernel** — this tier is the only thing
  that genuinely needs the polyglot path, and only for the few accumulation kernels.
- **bounded** — where the actual detection guarantee lives, and it is a **pair**:
  (a) the analytic CFAR/Neyman-Pearson closed-form Pfa, *tagged conditional on the
  noise model holding*, and (b) a **distribution-free empirical bound via conformal
  prediction** (finite-sample, exchangeability-only, model-agnostic; the 2025–26
  anomaly-detection literature validates it for false-alarm-rate control). Conformal
  is **native Python** — canon's real detection guarantee needs no proof assistant.
- **well-formed** — SHACL fold + metamorphic property tests (Hypothesis:
  scale-equivariance, monotonicity-of-statistic-vs-SNR) + contracts
  (icontract/deal, CrossHair on the pure-Python glue). The floor every detector
  earns.

**Per-result demotion (canon-novel).** A lightweight runtime monitor checks whether a
method's preconditions held on *this* input (CFAR's homogeneous-reference-window;
the feed was live). Its verdict is recorded in provenance and *selects the tier*:
assumptions violated ⇒ machine-checked-analytic → conformal-only → well-formed-only.
The tier a result earns is **computed, not asserted**. No prior system couples
runtime assumption-checking → tier selection → PROV record. This is the mechanism
that makes "honest per result" real.

## 5. The carrier — Belnap bilattice, `≤_k`-monotone

Every fold computes in **Belnap's four-valued bilattice** {None (no info), True,
False, Both (contradictory info)}, with two orders:

- **knowledge order `≤_k`** (None ≤ {T,F} ≤ Both) — *every fold must be monotone here.*
  Combining evidence only moves *up*: `None` is bottom; a fold can only add knowledge.
  This is the formal statement of **absence of evidence ≠ evidence of absence**.
- **truth order `≤_t`** (False ≤ {None,Both} ≤ True) — used *only* at the final
  detect/validate projection, where non-monotonicity is allowed because it's terminal.

Why Belnap over Kleene K3: a detector ensemble can both go *silent* (gap = `None`) and
*disagree* (`Both`). K3 has only one order and forces the SQL-`NULL`→`False` conflation
("we didn't look" becomes "we looked and it's clean") — the exact failure canon exists
to prevent. **`Both` is wired to the self-falsification machinery**: when an ∃-detect
path and a ∀-validate path disagree, the bilattice's contradiction value *is* the
soundness alarm — not a number to average away. Knaster–Tarski over the complete
lattice gives well-defined least fixpoints for recursive/self-referential detections.
*Borrow the monotone bilattice **algebra**, not any non-monotonic paraconsistent
**entailment** relation.* Content-addressing makes `None` explainable: a `None`
carries *which* input was missing as structural provenance ("no Sysmon 4688 in window").

## 6. The one seam that isn't free

Temporal negation under partial data. "C never occurred within W" is `True` given
*complete* data but must be `None` given *incomplete* data — a naive CEP engine
returns "negation satisfied / pattern matched" when really the C-feed is down or C
hasn't arrived yet. This is the absence-of-evidence trap, time-extended, and it is the
**only** cross-fold interaction that doesn't compose for free. Mitigation: temporal
negation is three-valued, gated on **feed-liveness** — "C-absent ∧ feed-healthy ⇒
True" vs "C-absent ∧ feed-silent ⇒ None". And feed-liveness *is* custody: a live,
unbroken feed is intact chain-of-custody, so the §3 custody fold supplies exactly the
signal the temporal fold needs. The hard seam closes against the keystone.

Two lesser interactions to design for, not discover: (i) order — confidence/partiality
folds are order-free (lattice/semiring), temporal is order-sensitive (event-time), so
**temporal state lives *beside* the timeless content-addressed DAG as an annotation
stream, never as DAG mutation**; (ii) two axes — graded belief (log-odds) and knowledge
value (`Both` ≠ "confidence 0.5") are orthogonal and must both be carried per node, not
collapsed into one scalar.

## 7. Borrow ledger (right thing, right joint)

- computation provenance → **W3C PROV-O** (+ RDF 1.2 triple terms for edge annotation)
- chain of custody → **in-toto Statement + DSSE**; forensic vocabulary from
  **CASE/UCO** (subset); signed entry claims from **W3C Verifiable Credentials**
- node identity → **IPLD multihash/CID**
- substrate structure → **Build Systems à la Carte** (Applicative + constructive
  traces + suspending); incremental layer (only if mutable inputs arrive) → **Salsa**
  durability + red-green early-cutoff
- well-formedness → **SHACL** (pySHACL)
- machine-checked numerics → **Flocq/Gappa/Coq**, or **F\*/Low\*→C**
- distribution-free detection guarantee → **conformal prediction** (+ SPRT/SMC at
  calibration)
- confidence fusion → **Chair–Varshney LLR** as a **probabilistic circuit**
- temporal → **CEP/chronicle** (Dousson; Morin & Debar for IDS) + **STL robustness**
  (RTAMT); timed automata as proof backstop
- partiality → **Belnap–Dunn bilattice**, `≤_k`-monotone algebra

## 8. Wheel-vs-novel ledger (what to claim)

**Known wheels (do not claim novelty; inherit the proofs):** the content-addressed
lazy DAG (Merkle/IPLD + Build-Systems-à-la-Carte); dedup-by-hashing; value-as-a-fold;
PROV-O; in-toto custody; SHACL; conformal prediction; Chair–Varshney; CEP/STL; Belnap.

**Genuinely canon (the contribution = composition aimed where no single wheel points):**
1. **One-hash-three-roles** — CID = Merkle id = PROV Entity = in-toto digest, joining
   computation-provenance to chain-of-custody in one addressing scheme.
2. **Co-equal folds of one tamper-evident object** — value, provenance, validation, and
   guarantee as peer interpretations of the *authoritative* content-addressed structure
   (provenance/build/SAC systems each do one of these; none unify them).
3. **Per-result guarantee tier that demotes** when runtime assumptions/feeds didn't hold,
   recorded in provenance — honesty as a computed property.
4. **Analytic + conformal pairing** as a single bounded-tier certificate, the substrate
   tracking which is load-bearing for each result.
5. **`≤_k`-monotonicity as a CI-checkable invariant** per fold; **`Both` wired to
   self-falsification**; correlation/missing-input made **structurally** detectable by
   content-addressing (shared node = shared evidence; `None` carries what was absent).

## 9. Open questions / risks

- **Independence in confidence fusion.** Radar-derived detectors share input data →
  correlated false alarms; naive LLR fusion is overconfident. Content-addressing makes
  shared-evidence *detectable* (shared sub-DAG = same node) but the correlation model
  (copula / shared latent / per-node cap) is unspecified. Resolve before the confidence
  fold ships.
- **RDF 1.2 Full/Basic interop cliff** (triple terms still CR) — gate behind the fold.
- **Conformal under distribution-shift / contaminated reference** is active research
  (2025–26) — borrowable, but treat shift-robustness as a known soft spot, not settled.
- **Calibration ≠ combination** — reported Pfa/Pd are often miscalibrated; calibration
  (Platt/isotonic/conformal) is a separate upstream fold, or all fusion is garbage-in.
- **Per-paper guarantee constants** from the survey need a confirming primary-source read
  before being cited in a shipped certificate.
