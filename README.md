# canon

**A substrate where no result is asserted that isn't justified back to its inputs and shown on demand —
where the justification of a result *is the same object* as the result, not a log written beside it.**

canon is a research and learning artifact, not an adoption play. It must stand as an object of thought on
its own *and* actually work; working is necessary, not sufficient. It is the deliberate inversion of how
AI systems present themselves today — fluent, confident, and unjustified.

## The one structural idea

> Every cross-cutting concern is a **`≤_k`-monotone fold** from one content-addressed computation DAG into
> a partially-ordered carrier (a **Belnap four-valued bilattice**).

That single sentence is the joinery. Three things follow from it:

- **The concerns compose because they share a shape.** Value, provenance, custody, validation, guarantee,
  confidence, temporal matching, partiality — each is a homomorphism over the same DAG into its own
  carrier. Homomorphisms over a fixed structure are independent: each reads the node set and its own
  carrier, nothing else.
- **The acceptance test is a theorem, not a vibe.** "Add concern N without touching concern M" is exactly
  `≤_k`-monotonicity of each fold — CI-checkable. Every fold ships a property test that feeds `None`/`Both`
  and asserts no knowledge-order violation. A fold that can't be written monotone is rejected and re-cut.
- **Justification is not metadata.** Provenance, custody, validation, and guarantee are folds *of the
  authoritative structure*, not side-logs. So the warrant for a result is the same object as the result,
  and it survives composition instead of being dropped at the first aggregation step.

The DAG itself is **not novel and is not defended as such** — it is a Merkle DAG with IPLD CIDs, sitting at
a known point in *Build Systems à la Carte* (applicative task, constructive traces, suspending scheduler).
Naming it correctly inherits decades of proofs. `design/` carries an explicit **borrow ledger** and a
**wheel-vs-novel ledger** separating what is taken from where from what is actually canon's.

## Layout

**`contracts/` is the base everything else falls out of** — the language-independent source of truth for
the contracts every joint mates through. It is deliberately *not* a Python package: if it were, Python
would own it, and no second binding could treat it as shared truth. This is canon's **narrow waist** (the
IP-hourglass / WASM / LSP pattern) — one stable interchange at the center, implementations varying freely
above and below.

Contracts: `cid.md` (content-address computation), `carrier.md` (the Belnap bilattice and the universal
`≤_k` invariant), `fold_protocol.md` (what a fold is, and its locality/monotonicity/totality
requirements), `guarantee_certificate.schema.json` (per-node tier + recorded absence),
`custody.md` (in-toto/DSSE at the ingest boundary), `detection_verdict.schema.json`, `shapes/` (SHACL).

| Package | What it is | LOC |
|---|---|---|
| `provenance` | The fold substrate — CID-addressed DAG, the folds themselves | 3.1k |
| `forge-core` | Domain-agnostic signal-analysis spine: features, tests, FP control. No domain assumptions | 5.8k |
| `detection` | Telemetry semantics above forge-core — real events → candidate streams → canonical `DetectionVerdict` | 19.0k |
| `semantic-core` | Typed wrappers over rdflib / owlready2 (OWL DL) / pySHACL, plus FCA implication-basis extraction | 1.3k |
| `semantic-cyber` | D3FEND as the defensive knowledge graph, ATT&CK as the offensive one; local counter-derivation via SPARQL over OWL restrictions | 2.5k |
| `omega` | Cross-corpus detection-knowledge map — where rule libraries overlap, diverge, and are silent, on an ATT&CK spine | 1.8k |
| `synthcyber` | Standalone generator of correct-by-construction labeled cyber datasets. Depends on nothing in canon | 0.4k |
| `kdc` | A KDC that *keeps the ledger* real KDCs don't, making golden/silver-ticket forgery checkable ground truth | 0.5k |

Also: `design/` (48 documents — the architecture, the ledgers, and the probe findings), `range/` (real
capture ranges), `rust/` (a motif emitter spike), `web/` (visualization surfaces).

## Status

Honest accounting, as of 2026-08-06:

- **978 tests pass, 3 skip, 0 fail** (`uv run pytest -q`, ~3m20s). The three skips are corpora-absent
  guards — vendored Sigma / OTRF / D3FEND / faker-kerberos and the `rdflib[rdf]` extra degrade gracefully
  so a bare runner stays green.
- **The contracts are PINNED and mechanically ENFORCED — for the Python binding.** The *polyglot* claim is
  not validated: there is exactly one binding, so these are "Python's interface, enforced," not yet proven
  language-independent. That is the honest state, not a roadmap promise.
- **The repo is currently shaped by its first serious use case.** `detection` is over half the code. The
  fold substrate and the contracts are meant to be domain-agnostic and `forge-core` is written that way,
  but the load-bearing exercise so far has been detection engineering, and it shows.
- `semantic-core`'s `Lattice` output is still a local Protocol rather than bound to `mathabc.order.Lattice`
  — that binding waits on `mathabc-core` being extracted into the workspace.

## Run it

```bash
uv sync
uv run pytest -q
```

Python ≥ 3.11 (the workspace pins 3.12). CI runs the same command on every push.

Corpora are fetched, never vendored — see each package's README (e.g.
`uv run --package semantic-cyber python scripts/fetch_d3fend.py`).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
