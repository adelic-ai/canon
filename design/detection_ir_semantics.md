# Detection-IR semantics profile — the pinned operational semantics every emitter targets

**Status: spec, 2026-06-18. Partly enforced.** The motif IR (`design/detection_ir_motif_ontology.md`) emits to
Python, SPARQL, and (scoped) Rust. Structure ports trivially; **semantics do not** — `.lower()` ≠
`to_lowercase()` ≠ `LCASE()` off-ASCII; `str(True)` ≠ `true`. So the IR must fix its *own* string semantics, and
each emitter conforms to **this spec**, not to its language's defaults. Agreement (`attest_emitter_agreement`)
then verifies conformance instead of hoping for it. This is what makes "translates to any language" a checked
property rather than per-language luck.

## Why a spec, not a convention

An emitter that uses its language's native string ops is correct *by accident* only where those ops happen to
coincide (ASCII). The cross-emitter gate will flag every divergence as a disagreement — but a flag is only
actionable if there is a *spec* saying which side is right. This doc is that spec. Each clause is a decision
with a stated trade-off, not a description of current code.

## The profile

<<<
case-fold        ASCII-only: A–Z ↔ a–z; every other code point is left UNCHANGED.
                 NOT full-Unicode folding. Identical across Python (str.translate), Rust
                 (make_ascii_lowercase), and a byte-wise SPARQL fold — so emitters agree by
                 construction on this operator. Trade-off: non-ASCII case variants (É/é, İ/i,
                 ß) are NOT folded; accepted for portability + determinism (full-Unicode
                 folding has its own cross-impl divergence AND its own evasion surface).

equality (eq)    exact string equality AFTER case-fold of both sides.

contains /        substring / prefix / suffix over the case-folded strings, on Unicode scalar
startswith /      values (= UTF-8 char boundaries). Python code-point ops and Rust &str ops
endswith          AGREE for valid UTF-8; JSON input guarantees valid UTF-8, so this operator
                  is portable as-is. No normalization (NFC/NFD) is applied — pinned: compare
                  raw scalars, not normalized forms.

value coercion    a STRING field value is used verbatim. The rule pattern is used verbatim
                  from the rule. NON-string event values coerce to their JSON lexical form:
                  bool → "true"/"false", integer → decimal, null → "" (absent). NOTE the
                  current Python oracle still uses Python str() here (→ "True"/"None"); this
                  is the one place the code lags the spec — unexercised by today's string-field
                  rules, reconciled when the Rust emitter forces it (see Open items).

missing field     an absent referenced field → "" (empty string). Consequence (pinned):
                  endswith/startswith/contains against a non-empty pattern → False; against an
                  EMPTY pattern → True (vacuous). Both the Python emitter and the SPARQL event
                  serializer already default absent fields to "".

list spec         a list of values is OR by default; the |all modifier makes it AND.

wildcards         `*` and `?` are treated LITERALLY in the current subset — NOT globbed. This
                  is a KNOWN NON-CONFORMANCE with real Sigma (which globs). See Open items — it
                  is the highest-priority correctness gap, ahead of the case-fold nicety.
>>>

## Per-emitter conformance

<<<
emitter   case-fold              status
Python    ASCII (this slice)     CONFORMS — `_ascii_lower` replaces `str.lower()` in
          (oracle)               `field_matches`; non-regressive on ASCII (Windows paths/DLLs),
                                 so all existing Sigma tests are unchanged.
SPARQL    LCASE (Unicode)        CONFORMS ON ASCII INPUT ONLY. `LCASE()` is full-Unicode; it
                                 agrees with the ASCII pin on ASCII data (hence OTRF agreement
                                 stays green) but diverges on non-ASCII. The one open
                                 non-conformance — fix with a byte-wise A–Z fold (nested REPLACE
                                 or a UDF) when the adversarial corpus lands.
Rust      make_ascii_lowercase   TO BUILD — targets this spec directly (byte ASCII fold), so it
          (scoped)               is conformant by construction.
>>>

Conformance is **measured, not asserted**: `attest_emitter_agreement` runs the emitters over a corpus and any
divergence localizes to *(emitter, event, rule)*. OTRF is the ASCII happy path; the real conformance test needs
an **adversarial corpus** that exercises the clauses above (non-ASCII case, bools/numbers, empty strings,
wildcards) — which is exactly where the dataset-generator earns its keep.

## Open items (honest, ordered by correctness impact)

1. **Wildcards (highest).** The subset treats `*`/`?` literally, so a rule like `CallTrace|contains:
   'python3*.dll+'` is mis-evaluated — it would *miss* a real `python311.dll+` that genuine Sigma *matches*,
   silently turning a covering rule into a false "gap" in the coverage map. Two honest fixes: implement glob
   semantics in the profile, **or** make `is_evaluable` *reject* wildcard-bearing specs so they abstain (NONE)
   rather than mis-evaluate. The latter is the canon-honest minimum (abstain > wrong) and the recommended next
   step. Deferred here to keep this slice non-regressive on the coverage tests.
2. **Non-string coercion.** Pin the Python oracle to the JSON lexical form (bool→`"true"`) to match the spec;
   currently uses `str()`. Unexercised by string-field rules today; reconcile with the Rust emitter.
3. **SPARQL non-ASCII case-fold.** Replace `LCASE` with a byte-wise A–Z fold for full conformance off-ASCII.
4. **Normalization.** Pinned to *no* NFC/NFD normalization; revisit only if a real rule needs it.

## This slice

Pins the spec (this doc) and brings the **Python oracle into conformance on case-fold**: `field_matches` uses
`_ascii_lower` instead of `str.lower()`. Because ASCII-lower equals Unicode-lower on ASCII, every existing Sigma
test is unchanged (verified) — the change is a *no-op on real rules today* and a *guarantee* tomorrow, when a
non-ASCII field would otherwise have made Python and Rust silently disagree. The motif Python emitter inherits
the fix for free (it reuses `field_matches`).
