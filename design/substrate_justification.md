# Substrate justification — borrowed tools, their application, and the composition

**Status:** DRAFT justification doc, 2026-06-25. Assembles the epistemic defense of *how* canon
uses Belnap / SKOS / FCA (and the other borrowed wheels) and *how their composition* is made
defensible. This is the internal, reviewable argument that must stand before any external paper.
Source-of-truth docs it assembles: [[self_validation_architecture]] (§7 borrow ledger, §8
wheel-vs-novel), [[guarantees_ledger]] (the epistemic register — the tests are the truth), the
contracts [[carrier]] / [[fold_protocol]], and the application sites in code. Where this doc and a
cited test disagree, the test wins.
**Correction 2026-06-25 (same day):** §6 / §9.1 / §7-table revised after verifying the code — the
value-aware `content_signature` over-collapse fix is already landed and wired (firing path + audit
bracket); the original draft trusted the stale [[project-content-digest-backlog]] note over the
repo. Dogfooding the doc's own rule: the test/code is the truth, the note was stale.

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
- **The carrier-choice argument (the one modeling claim a reviewer attacks):** *why Belnap, not
  Kleene K3 or a probability?* This was the doc's last open prose residue; it is now argued in full
  below (§2a), anchored to the carrier's actual `(t,f)` construction.
- **Verdict:** near-beyond-reproach. The algebra is inherited; the monotonicity is enforced, not
  asserted; and the carrier-choice argument (§2a) names the alternatives' failure modes rather than
  asserting Belnap.

### 2a. Why Belnap — not K3, not probability

Anchored to what the carrier *is* (`provenance/carrier.py`, `contracts/carrier.md`): `Four(t, f)`,
a pair of independent bits — `t` = "told true", `f` = "told false" — with `None=(0,0)`, `True=(1,0)`,
`False=(0,1)`, `Both=(1,1)`, and two non-interchangeable orders (`≤_k` knowledge, `≤_t` truth;
the ops are named functions, not overloaded operators, *precisely so the two never blur*).

**Why not K3 (Kleene three-valued: None/True/False, no `Both`).** K3 is *exactly* canon's carrier
minus `(1,1)`. It can hold ignorance (`None`) but not contradiction (`Both`). Canon's actual
workload is **multi-source fusion** — the Sigma panel, corroboration, cross-witness — where two
independent sources disagree: one tells-true `(1,0)`, one tells-false `(0,1)`, and their combination
is `Both=(1,1)`. K3 has nowhere to put it; it must collapse disagreement to one side or to `None`,
**silently erasing that the sources conflicted** — the one thing a fusion substrate must never drop.
The technical clincher: evidence accumulation is `⊕` = componentwise OR, and **`True ⊕ False = Both`**
(`contracts/carrier.md` truth table). Remove `Both` and that join has no value — *the
evidence-combiner is no longer closed.* K3 doesn't merely lack expressiveness; it **breaks the fold
algebra's closure.**

**Why not probability (`[0,1]`).** Probability collapses the two independent coordinates
(told-true, told-false) into one number, forcing `p_false = 1 − p_true`. That single move
destroys three distinctions canon depends on: (1) **ignorance vs equipoise vs conflict** all become
`0.5` — `None` (no evidence), genuine 50/50, and `Both` (two confident opposed sources) are
indistinguishable; (2) `p_false = 1 − p_true` **directly contradicts `None ≠ False`** (the
substrate's founding rule) — zero told-true is read as told-false; (3) there is **no information
order**, so `≤_k`-monotonicity — the universal invariant every fold is checked against — *cannot
even be stated*, let alone enforced. Magnitude/strength-of-belief is real and wanted, but it lives
in a **separate, later fold** (confidence / conformal demotion) layered on top, so graded numbers
never contaminate the monotone-fold invariant.

**The three failure modes, stated explicitly (what §2a buys):**
- **K3** → silent conflict-erasure + a non-closed evidence join (`True ⊕ False` has no value).
- **Probability** → ignorance/conflict/equipoise indistinguishable; `p_false = 1−p_true` contradicts
  `None ≠ False`; no information order, so `≤_k`-monotonicity is unstatable.
- **Belnap** (the honest costs canon accepts) → coarse (magnitude deferred to a later fold) + a
  two-order discipline burden (mitigated in code: named `≤_k`/`≤_t`, no operator overloading).

The choice is therefore not aesthetic: Belnap is the *minimal* carrier that (a) keeps the evidence
join closed under source-disagreement and (b) lets the `≤_k`-monotonicity invariant be stated at
all. K3 fails (a); probability fails (b) and the founding `None ≠ False` rule.

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

## 6. FCA — value-blind key, but the fix is landed and the blind key is confined

**Inherited:** Next-Closure / Duquenne–Guigues (proven). **Modeling claim:** rule-equivalence is
an FCA concept. There are now **two** concept keys (verified in code 2026-06-25):

- **value-blind `signature`** = `(logsource, field-set)` — **over-collapses** (value-distinct
  detections sharing a field-set merge; the 32-macOS-detections-→-1 finding;
  [[skos_graded_mapping_seam]], [[full_corpus_dedup_pass]]). Unsound as a general "these rules are
  equivalent" claim. `detection/sigma_panel.py::signature`.
- **value-aware `content_signature`** = `(logsource, content_digest of the compiled IR)` — the
  over-collapse fix: rules sharing a field-set but matching different VALUES get distinct keys.
  `detection/sigma_panel.py::content_signature`.

**The fix is landed and wired** (correcting an earlier draft of this section that listed it as
un-landed backlog — the source was the stale [[project-content-digest-backlog]] note; the code had
moved, and trusting the note over the repo is the exact failure this doc preaches against):

- The **recall-critical firing path keys on `content_signature`** (`detection/round.py`) — so
  value-distinct rules no longer collapse to one best-peer; the 32→1 *under-fire* hazard is closed
  **in the firing path**.
- **`audit.py` runs both keys to BRACKET redundancy** — field-set `signature` = the **upper bound**
  (over-collapse), `content_signature` = the **lower bound**; true redundancy is between them and
  needs the catch-set. The blind key here is explicitly labeled a *bound*, not an equivalence claim.
- The **value-blind `signature` survives only in two provably-safe uses:** the Sigma corroboration
  panel's **vote-dedup** (over-collapse only *under-counts* votes → more conservative; Belnap
  `TRUE`/`NONE`-never-`FALSE` compounds it) and audit's **bracket upper-bound**. The dead
  `concept_key` is not called anywhere (zero refs in `packages/`).

- **Verdict (revised — reproach CLOSED in code):** FCA is **no longer the most-attackable
  application in active use.** The unsound general-equivalence key is not in recall-critical use; it
  survives only where its error direction is provably safe (vote-dedup) or explicitly bracketed
  (audit bound). Both earlier residuals are now resolved: (a) `content_digest` is **verified
  filter-aware AND keyword-inclusive** — it folds *all* blocks (filter/negative + keyword blocks, as
  `(kind, field, ops, values, keywords)`) plus the condition AST that encodes `not filter`
  (`rule_ir.py::content_digest`, read 2026-06-25), so the original content-digest scope is met; (b)
  the cosmetic `round.py` comment mislabel was fixed by A (`speed/round-fca-comment-tidy`,
  `9743f70`). The **only remaining boundary is deliberate, not a gap:** `content_digest` is
  value-aware but *structural* — it cannot see *semantic* equivalence across differently-structured
  rules (`endswith \\x.exe` vs `contains x`; the same target via different fields). That ceiling is
  **catch-set's job, not content_digest's** — a designed division of labor, tracked separately, not
  an FCA reproach.

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
FCA value-blind key (general equivalence)              SCOPED-SAFE   value-aware content_signature landed +
                                                                     wired (round.py firing path, audit
                                                                     bracket); blind key confined to
                                                                     vote-dedup + audit upper-bound
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

1. **FCA scoping** — **CLOSED in code (verified 2026-06-25).** `content_signature` (value-aware) is
   landed and wired into the firing path (`round.py`) and the audit redundancy bracket; the
   value-blind `signature` is confined to provably-safe uses (vote-dedup, audit upper-bound);
   `content_digest` is verified filter-aware + keyword-inclusive (`rule_ir.py`); the comment mislabel
   is fixed (`9743f70`). No longer "the only unsound application in active use." The only residual is
   the **deliberate** structural-not-semantic ceiling, which is **catch-set's lane**, not FCA's.
2. **Carrier-choice argument** — **CLOSED (2026-06-25).** Argued in full in §2a, anchored to the
   carrier's `(t,f)` construction: K3 → conflict-erasure + non-closed evidence join
   (`True ⊕ False` has no value); probability → ignorance/conflict/equipoise indistinguishable,
   `p_false=1−p_true` contradicts `None ≠ False`, no information order so `≤_k`-monotonicity is
   unstatable; Belnap is the *minimal* carrier keeping the join closed and the invariant statable.
   Pure argumentation (the carrier itself is already PROVEN, §2/§7); no code side.
3. **SKOS proxy boundary** (standing guardrail) — ensure no artifact ever presents the structural
   edge as behavioral ground truth; the catch-set is the only thing that earns that word.
4. **Universality phrasing** (standing guardrail) — everywhere the "every concern is a fold" claim
   appears, it must read as an admission criterion, never as a proof.
