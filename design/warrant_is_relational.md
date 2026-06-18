# Warrant is relational — why the derivation, not the result, carries the trust

**Status: foundational framing, 2026-06-17.** The sharpest articulation of canon's core idea, recovered
in a session thread (RDF/OWL → reasoners → entailment → "is an ATT&CK technique a lemma or a hypothesis?").
It is *why the provenance graph has to exist*, stated from first principles.

## The claim

**Trustworthiness is a property of the derivation, not of the result.** A statement is just a statement
— its epistemic status is not *in* it. The string `anomaly = true` has no determinate trust-status on its
own; a `machine_checked`-backed one and an LLM-guessed one are the *same string* and not remotely the same
claim. So warrant cannot be read off a result; it must be **carried with** it.

## Warrant is relational — two relativities

- **Accuracy is relative to the premises (the world/model).** Under entailment, `Γ ⊨ φ` says φ is true *in
  every world where Γ holds*. Accuracy travels with the premises: change a premise and the same φ flips
  from accurate to not — the statement didn't change, its premise did.
- **Warrantable precision is relative to the mode of backing.** A proof/entailment gives **binary, exact**
  warrant — it follows or it doesn't, no fuzz, but only *relative to Γ*. Empirical/conformal backing gives
  **graded** warrant (a bounded probability). A guess gives **none**. Entailment *preserves* precision
  exactly; empirical *degrades* it to "probably." Same statement, different backing → different claimable
  precision.

So **"lemma vs hypothesis" is a property of the *derivation*, not the string.** "To dump LSASS you read
its memory" is a **lemma** relative to the Windows-spec axioms (entailed) *and* a **hypothesis** relative
to "the platform won't change" (Credential Guard refutes that premise). One sentence, two warrants, two
statuses — because status is relational.

## Frameworks are epistemically STRATIFIED, not uniformly "hypothesis"

The slogan "frameworks are validatable hypotheses; bedrock is logic + empirical reality" is right about the
*claim* layer and too flat about the *mechanism* layer. A single ATT&CK/D3FEND technique decomposes:

- **Definitional** — *what the technique is.* True by meaning, not falsifiable (an instance doing exactly
  X *is* X). "Attacks exactly as they are in ATT&CK" live here.
- **Mechanistic** — *what you necessarily must do* (or what a defense does). A **lemma relative to a
  platform spec** (`Kerberos ⊢ request a TGS`, `Windows ⊢ need PROCESS_VM_READ`). Provable, exact,
  necessary — *given the platform.* But the platform is a revisable engineering artifact (Credential Guard
  moves the secret), so it is a **lemma with a mutable premise** — bedrock-*ish*, not absolute.
- **Taxonomic** — tactic assignment, grouping, IDs. Curatorial convention, revisable.
- **Empirical** — who uses it, prevalence, procedure examples. Observational, fallible.
- **Coverage** — "the catalog is complete." Pure hypothesis.

So the mechanistic/definitional core is near-bedrock; only taxonomy/empirical/coverage are the hypothesis.
Treat the framework **non-uniformly**.

## Entailment inherits the weakest axiom

A reasoner's inference is *sound* (truth-preserving). But soundness preserves truth **from** the premises;
it doesn't establish them. So a conclusion derived over a framework **inherits the epistemic grade of its
weakest axiom**: rest only on mechanistic axioms → sound *and* well-grounded; lean on a coverage or
tactic-assignment axiom → sound-but-hypothetical. This is the [[project_skos_graded_mapping_seam]] idea
turned on the framework's *own statements* — grade the axioms by type (definitional / mechanistic /
taxonomic / empirical / coverage), and let the warrant fold over them by weakest-link, exactly as the
guarantee tier already folds.

## The consequence — why provenance must exist

Because warrant is relational and not intrinsic, it **must travel fused with the result**, unfakeable. That
fused object is precisely canon's verdict: **the statement PLUS its derivation (provenance graph) PLUS its
tier**, welded so the warrant can't be stripped off or forged. A result without its derivation has no
determinate epistemic status at all — which is the whole reason the provenance DAG is the same object as
the result (`design/self_validation_architecture.md` §1), not a side-log. This note is that principle's
"why," derived from the bottom up.
