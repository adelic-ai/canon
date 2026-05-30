# Version 2 — first principles / polyglot

**Status:** design, 2026-05-30. A realization of `self_validation_architecture.md`
(read that first). The truer object: define the joint system and its guarantee tiers
*abstractly*, then assign each joint its optimal material — Python, a proof assistant,
Rust, or a borrowed standard — treating today's Python as one candidate realization, not
the foundation. Square-one where the design earns it. This is the version where the
owner's "right material per joint" and "exploit code to its fullest potential" cash out.

**One-line verdict:** V2 buys exactly one thing V1 can't — the **machine-checked tier on
the numeric kernel** (bit-tight round-off + algebraic-identity certificates) — at the cost
of a second language per joint and specialist maintenance. It does **not** change the
bounded tier (still conformal) or the architecture (still folds over one CID-addressed
DAG). So V2 = V1's spine + a verified-numerics joint, made language-agnostic at the seams.

## The discipline: contracts at joints, not a rewrite

Treat each borrowed standard as an **interface contract at a joint**, specified
independently of any implementation language:

- **Node identity** — an **IPLD multihash/CID** *contract*: a digest is simultaneously the
  PROV Entity identity and the in-toto subject/product identity. Specified as a
  content-addressing contract so *any* language that computes the same CID sees the same
  DAG (Unison's interop property). This makes the substrate polyglot-addressable by
  construction — the seam between a Rust signing tap and a Python evaluator is a shared hash.
- **Computation graph** — **PROV-DM** as a language-agnostic model; the Entity/Activity
  structure is data, not a Python object.
- **Custody** — **DSSE + in-toto Statement** as a wire format (any language). Implement the
  ingest tap *where it lives* — plausibly Go/Rust at the log boundary for signing
  throughput, not Python.
- **The "full justification" object** — specified as a **serialization format**
  (PROV-O RDF + embedded DSSE envelopes + VC), not a runtime object, so the forensic answer
  is portable and independently verifiable *without canon's runtime*. This is the artifact
  that proves the thesis: hand someone the justification, they verify it cold.

## Joint-by-joint material assignment

- **Core substrate** — don't import Salsa-the-Rust-crate (its red-green machinery solves
  *incremental recompute*, a secondary concern for canon). The right first-principles
  skeleton is **Build-Systems-à-la-Carte made concrete**: a `Task` interface (Applicative),
  a pluggable `Rebuilder` over a CID store (constructive traces), and interpreters as folds
  — literally the paper's `newtype` structure ported to the host. Tagless-final over
  free-monad *if* the host is typed and you want compile-time-checked interpreter
  completeness. Host language: a typed functional core (the carrier + folds want algebraic
  data types and pattern matching — OCaml/Haskell/Rust/Scala all fit; the choice is the
  one genuinely-open call below).
- **value / provenance / well-formed / custody / confidence / temporal / partiality** — same
  folds as the spine; in V2 they're defined against the contracts above, so each *could* be
  implemented in a different host and still interoperate by CID. Belnap carrier + `≤_k`
  invariant are language-agnostic algebra.
- **guarantee — machine-checked tier (the reason V2 exists):**
  - *round-off bound* → **Coq/Rocq + Flocq + Gappa**, or **Frama-C/ACSL + Why3 + Gappa** if
    the kernel is C. Produces a checker-revalidatable certificate: "implemented statistic
    within ε of exact real." Apply to the **accumulation kernels** (Welch averaging, CUSUM
    sum, Goertzel recurrence) — the 2025 Floating-Point-Accumulation-Network results fit
    these directly.
  - *algorithmic identity / verify-once-ship-native* → **F\* + Low\*/KaRaMeL → C**
    (HACL\*-proven pipeline): the executable kernel *is* the verified artifact, no
    spec/impl gap; numpy calls it via `cffi`. Use for identities like Goertzel ≡ single-bin
    DFT magnitude, CFAR threshold monotonicity.
  - *integer/index/buffer logic* → **Dafny** or **Verus** (Rust) — **not** the float math
    (Verus has no floating point; Dafny reasons over exact reals unless bolted to Gappa).
  - The verification joint lives **off the executable path**, emits a content-addressed
    certificate, and the executable joint references it by hash. The DAG node is the
    contract between the two; they never need to be the same language.
- **guarantee — bounded / well-formed tiers** — *unchanged from V1*. Conformal prediction is
  still the distribution-free Pfa bound (no proof assistant replaces it); SHACL + metamorphic
  + contracts still the floor. Polyglot does not touch this. State this plainly so the
  polyglot budget isn't misspent chasing proofs of distributional claims.

## Where the polyglot budget actually buys something

Only the **machine-checked numeric tier**, and only on the **few accumulation kernels** where
a bit-tight round-off/identity certificate has real value. Everything else (custody, provenance,
the folds, conformal) is either already optimal in a mainstream language or unaffected by
verification language. Spend Coq/F\* effort surgically; the rest of V2's value is in the
*contract discipline* (CID/PROV/DSSE as language-agnostic seams), not in rewriting working code.

## The one genuinely-open call (owner's, not mine)

**Host language for the typed functional core.** The carrier (Belnap bilattice) + folds want
algebraic data types, pattern matching, and ideally compile-time interpreter-completeness
checks. Candidates, honestly:
- **Rust** — strong types, performance, `cffi`/FFI to the verified C kernels and to Python;
  no GC; but heavier to express the algebraic fold protocol than an ML.
- **OCaml/Haskell** — the natural home for tagless-final folds and Build-Systems-à-la-Carte
  (it's literally Haskell in the paper); cleanest expression of the joinery; weaker numeric
  ecosystem, but the numerics are at the verified-C / conformal-Python joints anyway.
- **Stay Python for the core, polyglot only at the verified-numerics joint** — i.e. V2 ≈ V1 +
  a Coq/F\* numeric joint, declining the functional-core rewrite. The pragmatic middle; loses
  compile-time fold-completeness checking.

This is the load-bearing fork and it's a craft/learning judgment, not an engineering one —
it decides how much of canon becomes an object built in the material that best expresses it
versus how much stays in the prototyping material.

But the **core-vs-periphery seam** (see the spine doc, §2 "narrow-waist seam") shrinks this
fork to a smaller, later, lower-regret decision than it looks: the CID interchange means the
host language commits *only the core* (the tight folds over the live DAG + carrier). Every
peripheral joint — custody, numeric proof, provenance export, SHACL, conformal — plugs in by
CID + standard format regardless, so a Python core can already carry an F\*-verified-C numeric
joint and a Go custody tap. So "stay Python core + polyglot joints" is not a lesser option but
the architecture as designed; the host-language pick can be deferred and swapped against the
V1 prototype, since no peripheral joint imports the core.

## V1 ↔ V2 relationship

They are not either/or. V1 is the executable spine and ships the bounded/well-formed tiers
(canon's real guarantee). V2 is V1 with (a) the seams re-specified as language-agnostic
contracts and (b) a verified-numerics joint added for the machine-checked tier. The honest
path is likely: **build V1, then lift specific joints to V2** — re-specify identity/custody as
CID/DSSE contracts, then add Coq/F\* certificates to the accumulation kernels — rather than a
from-scratch polyglot build. Square-one is reserved for the functional-core question above, if
the owner decides the joinery deserves a material that expresses it better than Python.
