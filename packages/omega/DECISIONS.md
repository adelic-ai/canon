# DECISIONS

Judgment calls made while building the ATLAS ingest + coverage cartography (ATLAS-SPEC.md), recorded per
the operating discipline: the doc was ambiguous or silent on these, so I decided and proceeded rather than
blocking. Each entry: the call, why, and the alternative rejected.

## ATLAS is a new IR type (`AtlasTechnique`), not a reused `CompiledRule`

**Call:** added a new frozen dataclass in `ir.py` for spine nodes, instead of lowering ATLAS techniques
into `CompiledRule` (empty `blocks`, ATT&CK refs stuffed into `tags`).

**Why:** `CompiledRule` is rule-shaped — blocks, polarity, a condition. An ATLAS technique has none of
that; it's a taxonomy entry. §3.1 asks for fields `CompiledRule` doesn't have at all (tactic membership,
subtechnique parentage) and doesn't need fields `CompiledRule` requires (condition, polarity). Forcing the
fit would either drop real data or assert structure that isn't there — exactly the kind of forced sameness
the CAR adapter's docstring already warns against for a much smaller mismatch (CAR at least has one-rule-
one-analytic; ATLAS has no rule at all).

**Rejected alternative:** reuse `CompiledRule` with empty `blocks=()`, `tags` = ATT&CK refs. Rejected
because it would make `AtlasTechnique` instances silently flow into `axes.attributes()` and FCA/SKOS as if
they were rules — comparable-for-sameness against Sigma/CAR rules, which they structurally aren't. The
whole point of §1 ("ATLAS is a spine, not a corpus") is that it does NOT get treated like a third ruleset.

## The transitive bridge lives in `coverage.py`, not inside `axes.py`

**Call:** the `atlas` axis (`axes.py`) only handles *direct* rule→ATLAS tagging (a per-rule token, exactly
like `attack`). The rule→ATT&CK→ATLAS transitive walk is a new module, `coverage.py`.

**Why:** `axes.attributes(ir, *, axes)` is a pure per-rule projection with no corpus-level context. The
bridge needs the whole ingested ATLAS spine (which ATT&CK ids map to which techniques) to answer "does
this rule reach ATLAS at all" — that's not a projection of one rule, it's a join across two corpora, the
same shape `report.cross_corpus` already is. Keeping `axes.py`'s contract untouched (no new parameters)
also matches §1's "new code is one ingest adapter and one axis; everything above is unchanged" — the axis
itself IS unchanged in shape, it just gained one more direct-echo case.

## Subtechniques do not inherit the parent's `tactics`

**Call:** `ingest/atlas.py`'s `to_ir` reads a subtechnique's own `tactics` field only; a subtechnique that
lists none gets `tactics=()`, even though its parent technique (found via `specializes`) may have some.

**Why:** ATLAS's compiled data states tactics explicitly per node; inventing inheritance asserts a
membership claim the source data doesn't make (a subtechnique can legitimately narrow to a subset of its
parent's tactics, or none of them, and the compiled file just doesn't say). This isn't load-bearing for the
coverage classifier (tactics aren't read there at all), but it matters for anyone reading `table()` rows or
building on `AtlasTechnique` next — "silent" fields should read as silent, not as a guess dressed as data.

## "CAR-coarse" = CAR is the ONLY ruleset that reaches a technique

**Call:** `uncertain(CAR-coarse)` fires only when every rule bridging to a technique is CAR-sourced; if a
Sigma rule also reaches it, the technique reads `covered(bridged)` and the CAR evidence is folded in
silently (not surfaced separately).

**Why:** §5's caveat is specifically that CAR's ATT&CK-coverage tag isn't corroborated by parsed detection
logic the way Sigma's clause is — so CAR-only coverage is a **blind spot in what omega can verify**, not a
statement about the technique itself. Once a Sigma rule (parsed, verifiable) also reaches the technique,
the uncertainty that mattered is resolved — the technique genuinely has covered-quality evidence, and
continuing to flag it as uncertain would just be noise ATLAS-SPEC.md never asked for.

**Rejected alternative:** track CAR involvement as a separate flag on every covered row regardless of
Sigma presence. Rejected as scope creep past the five-way status §6 explicitly asks for; provenance
(`rules`, `via`) already shows which corpus actually supplied the covering rule(s) for anyone who wants it.

## A direct ATLAS tag is not subject to CAR-coarseness

**Call:** `covered(direct)` is unconditional on ruleset — a CAR analytic that directly carries an ATLAS tag
would count as `covered(direct)`, same as Sigma.

**Why:** §5's coarseness caveat is about CAR's **unparsed query logic** standing in for real detection
evidence when the only path to a technique runs through the ATT&CK bridge. A direct ATLAS tag is a
first-class structured assertion (like CAR's `coverage` field itself) — not something that depends on
parsing SPL/EQL. There is no real-world case today (no rule library tags AML.Txxxx directly yet), so this
is a forward-looking default rather than a load-bearing call; noted in case it matters once one exists.

## No `data/` source-tree fallback for the ATLAS ingest

**Call:** the adapter only reads the compiled `dist/ATLAS.yaml` (or a checkout root containing it); §2's
fallback to the `data/` tree "if the compiled form lacks a field" is not implemented.

**Why:** every field the coverage cartography needs — `id`, `name`, `tactics`, `specializes`,
`ATT&CK-reference` — is present in the compiled file (verified against the real corpus, not just the
schema docs). The fallback exists in the spec for a field that might be missing; none is. Adding a `data/`
parser now would be speculative generality for a need that hasn't shown up.

## Mitigations and case studies are read but not lowered to IR

**Call:** `ingest/atlas.py` reads the ATLAS.yaml file whole but only lowers `matrices[].techniques` to
`AtlasTechnique`; `mitigations` and top-level `case-studies` are ignored.

**Why:** §3.3's coverage table is technique-keyed; neither mitigations nor case studies carry an ATT&CK
cross-reference or a coverage-relevant field. Ingesting them would be dead weight against this build's
actual output. Noted as explicitly out of scope, not forgotten.

## Out of scope (per §7, restated for the record)

- CAR ingest stays exactly as it is — no query-logic parsing added, `uncertain(CAR-coarse)` is the honest
  ceiling on what omega can say about CAR-only paths.
- Mapping agentwatch's own detector coverage onto ATLAS is a separate, later job (§0/"why it stands alone").
