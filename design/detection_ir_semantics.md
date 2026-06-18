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

wildcards         Sigma glob: `*` → any run (incl. empty), `?` → exactly one char; compiled to an
                  ANCHORED, DOTALL regex (`sigma_eval.glob_regex_body`, a full match). Escape
                  convention: `\*` `\?` `\\` are the literal char, a lone `\` is a literal
                  backslash, and every literal run is regex-escaped — so `.` in `comsvcs.dll`,
                  `+` in `lsass.exe+`, and backslash paths stay LITERAL (the naive `replace('*',
                  '.*')` would break on all of these). Modifiers are glob sugar: contains x ≡
                  `*x*`, startswith ≡ `x*`, endswith ≡ `*x`. The single regex `glob_regex_body`
                  is what every emitter compiles, so they glob identically by construction.
>>>

## Per-emitter conformance

<<<
emitter   case-fold   wildcards   status
Python    ASCII       glob        CONFORMS on both. `_ascii_lower` + `glob_regex_body` in
          (oracle)                `field_matches`; non-regressive on real rules (38+ tests
                                  unchanged), and the glob is verified EXHAUSTIVELY vs stdlib
                                  `fnmatch` (test_glob.py) + a golden escaping table.
SPARQL    ASCII       glob        FULLY CONFORMS. case-fold: event values are PRE-FOLDED with the
          (pre-fold)  (REGEX)     oracle's `_ascii_lower` at serialization (`eval_sparql`), so the
                                  query needs no `LCASE` (`lhs` is `STR(?v)`) — ASCII-only and
                                  portable (no engine-specific lowering / no nested `REPLACE`).
                                  wildcards: `_filter_expr` compiles the shared `glob_regex_body`
                                  into anchored `REGEX(...,"s")` (fast string fns for plain values).
                                  Verified by the adversarial corpus + `attest_emitter_agreement` ↔
                                  the Python oracle: FULL parity, no residual. (rdflib REGEX uses
                                  Python `re`; a non-rdflib triple store may differ — re-attest there.)
Rust      ascii fold  glob        TO BUILD — targets this spec directly (byte ASCII fold +
          (scoped)                `glob_regex_body`), conformant by construction.
>>>

Conformance is **measured, not asserted**: `attest_emitter_agreement` runs the emitters over a corpus and any
divergence localizes to *(emitter, event, rule)*. OTRF is the ASCII happy path; the real conformance test needs
an **adversarial corpus** that exercises the clauses above (non-ASCII case, bools/numbers, empty strings,
wildcards) — which is exactly where the dataset-generator earns its keep.

## Open items (honest, ordered by correctness impact)

1. **Wildcards — RESOLVED in the oracle (2026-06-18).** `field_matches` now globs (`*`/`?` → anchored DOTALL
   regex via `glob_regex_body`, Sigma escape convention), so `CallTrace|contains: 'python3*.dll+'` correctly
   matches `python311.dll+` instead of producing a false gap. **Verified conclusively**: exhaustive differential
   vs stdlib `fnmatch` over a bounded alphabet (~10.5k pairs, an independent glob engine) + a golden escaping
   table; 46 field_matches-touching tests unchanged (non-regressive). The SPARQL emitter now compiles the same
   `glob_regex_body` into `REGEX(...,"s")` too — verified by `attest_emitter_agreement` ↔ the Python oracle on
   wildcard cases (rdflib REGEX = Python `re`). *Remaining for wildcards*: only the Rust emitter (targets
   `glob_regex_body` by construction when built) and re-attestation on a non-rdflib triple store.
2. **Non-string coercion.** Pin the Python oracle to the JSON lexical form (bool→`"true"`) to match the spec;
   currently uses `str()`. Unexercised by string-field rules today; reconcile with the Rust emitter.
3. **SPARQL non-ASCII case-fold — RESOLVED (2026-06-18).** `eval_sparql` now pre-folds event values with
   `_ascii_lower` (the oracle's fold) at serialization, so the query uses no `LCASE`. Verified by the
   adversarial corpus: Python ↔ SPARQL now agree on `nonascii_case` (both no-match) and on every other landmine
   — full parity, no residual.
4. **Normalization.** Pinned to *no* NFC/NFD normalization; revisit only if a real rule needs it.

## This slice

Pins the spec (this doc) and brings the **Python oracle into conformance on case-fold**: `field_matches` uses
`_ascii_lower` instead of `str.lower()`. Because ASCII-lower equals Unicode-lower on ASCII, every existing Sigma
test is unchanged (verified) — the change is a *no-op on real rules today* and a *guarantee* tomorrow, when a
non-ASCII field would otherwise have made Python and Rust silently disagree. The motif Python emitter inherits
the fix for free (it reuses `field_matches`).
