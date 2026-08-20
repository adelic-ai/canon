# canon

canon binds a result to the derivation and evidence that produced it, so the warrant for a claim travels
with the claim itself instead of sitting in a separate log someone has to go find.

canon is a research and learning artifact, not an adoption play — it has to work, and working is necessary
but not sufficient. `design/` records negative results alongside what worked: cases where a more
sophisticated method was tried against a real corpus and didn't beat a simple baseline, kept rather than
dropped.

> **[START-HERE.md](START-HERE.md)** routes you to the shortest path for whatever brought you here — the
> core idea, the enforcement contracts, the ontology work, or the cross-corpus mapping — and says what to
> skip. Most of this repo won't be what you came for.

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

## The one structural idea

Every cross-cutting concern above — provenance, custody, validation, guarantee, confidence, temporal
matching, partiality — is implemented as a **`≤_k`-monotone fold** from the same content-addressed
computation DAG into a partially-ordered carrier (a **Belnap four-valued bilattice**). That's the joinery
holding the packages in the table above together. Three consequences follow:

- **The concerns compose because they share a shape.** Each is a homomorphism over the same DAG into its
  own carrier. Homomorphisms over a fixed structure are independent: each reads the node set and its own
  carrier, nothing else.
- **"Add concern N without touching concern M" is CI-checked, not just claimed.** It reduces to
  `≤_k`-monotonicity of each fold. Every fold ships a property test that feeds `None`/`Both` and asserts no
  knowledge-order violation; a fold that can't be written monotone is rejected and re-cut.
- **Provenance, custody, validation, and guarantee are computed from the same structure that produced the
  result, not attached afterward.** The warrant for a result is bound to that structure and survives
  composition instead of being dropped at the first aggregation step.

The DAG itself is not novel — it's a Merkle DAG with IPLD CIDs, sitting at a known point in *Build Systems
à la Carte* (applicative task, constructive traces, suspending scheduler). `design/` carries an explicit
borrow ledger and wheel-vs-novel ledger separating what's taken from where from what's actually canon's.

## Status

Honest accounting, re-verified 2026-08-19:

- **1,003 tests, 0 fail** (`uv run pytest -q`) — but the pass/skip split depends entirely on whether the
  corpora are present:
  - *With corpora fetched:* **999 pass, 4 skip** (~3m20s).
  - *Clean clone, no `data/`:* **913 pass, 90 skip** (~1m). `uv sync` resolves from the lockfile with no
    intervention.
  - The 90 skips are corpora-absent guards — Sigma, OTRF, flaws.cloud CloudTrail, faker-kerberos,
    splunk-attack-data, D3FEND, and the `rdflib[rdf]` extra all degrade gracefully so a bare runner stays
    green. **This is the honest cost of "fetched, never vendored": a third party gets 913 tests, not 999.**
    The 86-test difference is exactly the real-data evidence, and reproducing it means fetching the corpora.
- **The contracts are PINNED and mechanically ENFORCED — for the Python binding.** The *polyglot* claim is
  not validated: there is exactly one binding, so these are "Python's interface, enforced," not yet proven
  language-independent. That is the honest state, not a roadmap promise.
- **The repo is currently shaped by its first serious use case.** `detection` is over half the code. The
  fold substrate and the contracts are meant to be domain-agnostic and `forge-core` is written that way,
  but the load-bearing exercise so far has been detection engineering, and it shows.
- `semantic-core`'s `Lattice` output is a local `Protocol`, and that is the intended surface — not a stub
  awaiting an external typed-math dependency. FCA extraction needs a partial-order contract its consumers
  can satisfy structurally; it does not need an algebra library.

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
