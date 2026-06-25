# Substrate justification — borrowed tools, their application, and the composition

**Status:** DRAFT justification doc, 2026-06-25. Assembles the epistemic defense of *how* canon
uses Belnap / SKOS / FCA (and the other borrowed wheels) and *how their composition* is made
defensible. This is the internal, reviewable argument that must stand before any external paper.
Source-of-truth docs it assembles: [[self_validation_architecture]] (§7 borrow ledger, §8
wheel-vs-novel), [[guarantees_ledger]] (the epistemic register — the tests are the truth), the
contracts [[carrier]] / [[fold_protocol]], and the application sites in code. Where this doc and a
cited test disagree, the test wins.

## 0. The thesis of this document

Canon's defensibility is **not** "we proved our tools are universally correct." It is **"every
claim is scoped to exactly where it holds, and that scoping is mechanically enforced or honestly
recorded."** Two consequences set the whole frame:

- **You do not prove Belnap, FCA, SKOS, conformal prediction, Chair–Varshney, SHACL.** These are
  inherited wheels with their own proofs; canon cites them and must *not* claim novelty for them.
- **The justification burden is on two things only:** (a) each **modeling choice** — "concern X
  *is* a `≤_k`-monotone fold," "rule-relatedness *is* a SKOS graded edge," "rule-equivalence *is*
  an FCA concept" — which is an argument, not a theorem; and (b) the **composition** — that the
  folds combine into one coherent, tamper-evident object. (b) is the genuinely novel contribution.

"Beyond reproach" is won by honest scoping. "Strongly arguable" is the honest ceiling for the
modeling choices. The composition claim is the one place a *near-theorem* is available.

## 1. The inherited wheels (cite; claim no novelty)

Inherited, proven elsewhere, used as-is. Novelty claim on any of these = a reproach.

- **Belnap–Dunn four-valued bilattice** — the carrier algebra (two orders, truth tables, lfp).
- **FCA** — Ganter's Next-Closure (concept enumeration), Duquenne–Guigues (implication basis).
- **SKOS** — the mapping vocabulary (`exact/close/broad/narrow/relatedMatch`).
- **Conformal prediction** — distribution-free finite-sample FAR bound (marginal).
- **Chair–Varshney** — Bayes-optimal LLR fusion given known operating points.
- **SHACL / PROV-O / in-toto-DSSE / IPLD-CID / Build-Systems-à-la-Carte** — the artifact and
  structure standards.

What canon adds sits *on top* of these, never *under* them.

## 2. The carrier (Belnap) — strong, mechanically enforced

**Inherited:** the bilattice algebra. **Modeling claim:** every cross-cutting concern can be
written as a `≤_k`-monotone fold into `FOUR = {None, True, False, Both}`.

- **What is proven (not just claimed):** the `(t,f)` model, all operation truth tables, negation
  monotonicity, and the complete-lattice/lfp basis are exhaustive over the 4-value domain
  (`contracts/carrier.md`; PROVEN in [[guarantees_ledger]], `provenance/carrier.py` ·
  `test_carrier.py`). The universal **`≤_k`-monotonicity invariant** is CI-checked per fold
  (`test_monotone.py`).
- **The arguable residue (must be argued crisply, currently prose):** *why Belnap, not Kleene
  K3 or a probability?* The answer is load-bearing: a detector ensemble can both go **silent**
  (`None`) and **disagree** (`Both`); K3 has one order and forces the SQL-`NULL`→`False` collapse
  canon exists to prevent, and a scalar probability cannot represent "two confident contradictory
  sources" (`Both` ≠ 0.5). This is the modeling argument, and it is the thing a reviewer attacks
  — so it must be stated as an argument with the failure modes of the alternatives, not asserted.
- **Verdict:** near-beyond-reproach. The algebra is inherited; the monotonicity is enforced, not
  asserted. The only soft spot is making the carrier-*choice* argument explicit.

## 3. The fold family and the four requirements

Eight folds (a ninth, `cost`, is designed-deferred), each `≤_k`-monotone over the one DAG:

1. **value** — topological evaluation to the concrete result.
2. **provenance** — `to_prov` → PROV-O (how the result was produced).
3. **custody** — in-toto/DSSE at ingest; integrity-in-transit only; `NONE` on unsigned.
4. **validity** — source-payload schema/kind conformance; carries the deviation; never `None`→drop.
5. **well-formedness** — SHACL over the materialized graph; earns the `well_formed` tier.
6. **guarantee** — per-node tier (`machine_checked`/`bounded`/`well_formed`/`absent`), demotable.
7. **confidence** — Chair–Varshney LLR in log-odds (OR≈sum, AND≈product).
8. **temporal** — CEP/chronicle + STL; three-valued negation under partial data.

**The four fold requirements (all CI-checkable, `contracts/fold_protocol.md`):** locality (reads
only node + children's results), `≤_k`-monotonicity, totality (handles every node variant),
determinism (pure function — no clocks/RNG; enables cross-language diff by CID). Single-output
folds; multi-concern passes are *composition*, not product folds.

## 4. The composition — the focal point, and where a near-theorem lives

The master claim: **every concern is a `≤_k`-monotone fold over one content-addressed DAG; folds
compose independently; justification is the same object as the result.**

- **Beyond reproach (mechanically enforced):** *independence.* Locality + single-output +
  monotonicity ⟹ "add concern N without touching M" — two folds over one DAG cannot interfere
  because neither reads the other's state. This is a near-theorem, and it is CI-checked. This is
  the strongest thing in the stack and the part a reviewer cannot wave away.
- **Justification-is-the-result:** because provenance/custody/validation/guarantee are *folds of
  the authoritative structure* (not side-logs), the justification of a result *is the same object*
  as the result. This follows from the fold being over the same DAG; it is structural, not a hope.
- **The one-hash-three-roles keystone:** a node's content-address is simultaneously Merkle id,
  `prov:Entity` IRI, and in-toto product digest — joining computation-provenance to chain-of-
  custody in one addressing scheme. PROVEN as an identity (`test_custody.py`).
- **The arguable residue (state correctly or it's false):** *universality* — "every concern canon
  cares about can be written as such a fold" is **inductive** (8 folds built, all monotone), not
  deductive. Do **not** write it as a proof. The honest, defensible framing is an **admission
  criterion**: canon *admits only* monotone-fold-expressible concerns; one that can't be written
  monotone is rejected and re-cut. Stated that way it is defensible by construction.
- **Per-result demotion (a distinct novel claim):** the guarantee tier a result earns is
  *computed* from runtime assumption checks and recorded in provenance, not asserted — honesty as
  a computed property (`provenance/guarantee.py`; conformal exchangeability monitor demotes
  `bounded`→`well_formed` on real drifting data, [[guarantees_ledger]] ASSUMED).

## 5. SKOS — a proxy, honestly scoped (the strongest available position)

**Inherited:** the mapping vocabulary. **Modeling claim:** rule-relatedness is a SKOS-graded edge
(`exact/close/broad/narrow/related`), read from the positive clause-set order (`detection/rule_lattice.py`).

- **Defensibility:** strong *as a scoped structural proxy.* The repo does not call it ground truth
  — it is explicitly a **structural** relation, a proxy for the **behavioral** catch-set, with the
  gap measured this cycle: behavioral synonyms are structurally `related`, not `exact` (under-group),
  and filter-blind `exact` pairs need not co-catch (over-group) (`detection/catch_set.py`,
  `ground_lattice`). A claim that states its own limit is defensible *because* it does.
- **Requirements that keep it honest:** the grade must be **justified and callable** (`.why()` —
  shared/unique clauses, sub-scores) and demotion into the verdict tier is **gated on
  load-bearingness** (a `closeMatch` on an unused field is inert) ([[skos_graded_mapping_seam]]).
- **Verdict:** beyond-reproach *if and only if* it is never represented as behavioral ground truth.
  The one failure mode is anyone (a paper, a verdict) treating the structural edge as "what the
  rule detects."

## 6. FCA — the weak application; scope it or fix it

**Inherited:** Next-Closure / Duquenne–Guigues (proven). **Modeling claim:** rule-equivalence is
an FCA concept keyed on `(logsource, field-set)`.

- **The soundness problem (documented, not hidden):** the concept key is **field-set, value-blind**,
  so it **over-collapses** — value-distinct detections fold into one concept (the 32-macOS-detections-
  →-1 finding; [[skos_graded_mapping_seam]], [[full_corpus_dedup_pass]]). As a general "these rules
  are equivalent" claim, this is **unsound**.
- **Where it is nonetheless safe:** the Sigma corroboration panel uses FCA for **vote-dedup** — one
  concept = one vote ([[guarantees_ledger]] VALIDATED, `detection/sigma_panel.py`). There,
  over-collapse **under-counts** votes — it can only make corroboration *more* conservative, never
  inflate it. The Belnap one-sidedness (`TRUE`/`NONE`, never `FALSE`) compounds the safety.
- **The rule:** FCA's claim must be scoped to **conservative vote-dedup**, never to general
  equivalence — or replaced by the value/filter-aware **`content_digest`** ([[project-content-digest-backlog]]).
- **Verdict:** **this is the single most attackable application in the stack.** It is safe where used
  today only by the conservative direction of its error; an unscoped "we dedup rules via FCA" is the
  reproach. Closing it (scope-in-writing or `content_digest`) is the highest-value justification fix.

## 7. Epistemic status — beyond-reproach vs strongly-arguable

Mapped to the register in [[guarantees_ledger]] (the tests are the truth):

<<<
claim                                                  status        defended by
Belnap algebra + ≤_k-monotonicity                      PROVEN        carrier.py / test_carrier, test_monotone
fold independence (add-N-without-M)                    PROVEN        fold_protocol four requirements, CI
one-hash-three-roles keystone                          PROVEN        test_custody
per-result guarantee demotion                          PROVEN/       guarantee.py, conformal monitor
                                                       ASSUMED
carrier choice (Belnap over K3/probability)            ARGUABLE      architecture §5 (prose — to harden)
"every concern is a monotone fold" (universality)      ARGUABLE      admission criterion, not a proof
SKOS edge as structural relation                       ARGUABLE/     rule_lattice; honest proxy
                                                       SCOPED        (must never = ground truth)
FCA concept = rule equivalence                         UNSOUND       over-collapse documented; SAFE only as
                                                       (scoped-safe) conservative vote-dedup
detection empirics (conformal/MI/IT advantage)         CAPPED/       guarantees_ledger — unproven on real data
                                                       UNPROVEN
>>>

## 8. What needs a paper vs a justification doc

- **This document** is the justification doc — the scoping that wins "beyond reproach." It is the
  prerequisite to any paper.
- **Paper-ready now (the real contribution):** the **composition architecture** — folds over one
  CID-addressed DAG, monotonicity-as-independence, justification-is-the-result, one-hash-three-roles
  — plus **per-result guarantee demotion** (honesty as a computed property). Defensible today
  *because the independence is mechanically enforced, not claimed.*
- **Not paper-ready (need data, not proof):** every *positive detection* claim — conformal-vs-
  baseline, MI-coordination, IT-features. [[guarantees_ledger]] records these CAPPED/unproven on
  real data. A paper here today is a negative-results/methodology paper at best, gated on the
  discriminating corpus. Do not let a paper smuggle them past their own register.
- **No paper (inherited):** Belnap, FCA, conformal, Chair–Varshney, SHACL — cite, don't claim.

## 9. Open reproach-risks to close

1. **FCA scoping** (highest value) — scope to conservative vote-dedup in writing, or land
   `content_digest`. Until then, the only unsound application in active use.
2. **Carrier-choice argument** — harden architecture §5 from prose into an explicit "why not K3 /
   why not probability," with the alternatives' failure modes named.
3. **SKOS proxy boundary** — ensure no artifact ever presents the structural edge as behavioral
   ground truth; the catch-set is the only thing that earns that word.
4. **Universality phrasing** — everywhere the "every concern is a fold" claim appears, it must read
   as an admission criterion, never as a proof.
