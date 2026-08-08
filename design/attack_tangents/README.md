# Attack tangents — a depth-first, grounded technique catalog

**Status:** working corpus, opened 2026-06-24. Two purposes at once, by design:

1. **Study notebook.** A place to go *deep* on attack techniques — the variants, the telemetry they
   live in, the way they branch and pivot. The unit of value is the **tangent tree**, not the technique
   label. MITRE already lists the techniques; what it can't give you is *your* analysis of how one
   actually splits (kerberoast → RC4 / AES / targeted → ticket-options fingerprint → honeypot SPN →
   the SPN→service-account cross-actor pivot).
2. **Structured grounding layer for detection.** Each note carries a machine-joinable spine
   (YAML frontmatter keyed by ATT&CK ID) plus a consistent signal→fidelity schema, so the catalog
   isn't just prose — it's the human-readable face of canon's coverage numbers (what the Sigma corpus
   *claims* vs what *catches*), and it's liftable to RDF when a consumer appears.

This is canon's edge made concrete: *framework-OWL is infra; grounding is the edge.* The annotations
**are** the grounding. Relates to [detection_battery](../../web/detection/detection_battery.html)
(framework as callable verifier),
[detection/fidelity_scorecard.py](../../packages/detection/src/detection/fidelity_scorecard.py)
(claims ≠ catches), [skos_graded_mapping_seam](../skos_graded_mapping_seam.md) (rule↔technique
mapping), and the chain checker (`detection/chain.py`).

## Principles

- **Depth-first, never breadth-first.** A catalog of *all* 600 techniques is MITRE re-listed — it adds
  nothing. Write notes for techniques you are actually studying, and go deep. *Mint, don't vendor:* no
  empty stubs for the whole matrix.
- **The base data is already local.** The ATT&CK bundle lives at
  `packages/semantic-cyber/data/enterprise-attack.json` (51M) with a parser
  (`semantic_cyber.attack`: `load`, `get_technique`, `subtechniques`, `tactics_of`). Notes join onto it
  by `attack_id` — no download, no re-vendoring of MITRE's own fields. We annotate; MITRE supplies the
  spine.
- **Honest data-availability.** Every note records whether canon can *test* the technique locally and on
  what data. Catch-rates that haven't been run on real data are **NONE, not zero** — a fact-vs-hypothesis
  distinction we hold strictly. The catalog doubles as a map of our **data-shape gaps**.
- **Fidelity is graded and additive.** Signals don't gate each other; each one *raises* confidence by an
  amount set by its fidelity (deterministic honeypot ≫ behavioral fan-out ≫ statistical ratio). Same
  additive-warrant pattern canon uses everywhere.

## Entry schema

Frontmatter (the machine-joinable spine):

```yaml
attack_id: T1558.003        # joins to the ATT&CK bundle
name: Kerberoasting
tactic: credential-access
parent: T1558
status: studying            # stub | studying | studied
data_available: false       # can canon test this locally with the REQUIRED fields?
sigma_claims: 17            # rules in OUR corpus tagging this id (measured, with date)
catch_measured: null        # NONE until run on real data — never fabricate a catch number
```

Body sections (consistent across entries, prose inside each):

- **Summary** — what it is, one paragraph, in our own words.
- **Variant tree** — the tangents. How the technique branches (the load-bearing study content).
- **Telemetry** — channels and fields it lives in; which are *required* vs *nice-to-have*.
- **Detection signals + fidelity** — each signal as `name — telemetry — fidelity — note`. Graded, additive.
- **Evasions** — and the "shadow of an absent/bypassable control" frame where it applies.
- **Kill-chain / cross-actor structure** — how it links to other stages; identity pivots.
- **Data availability** — the honest wall: can we test it, on what, what's missing.
- **Canon hooks** — claims (FCA/Sigma corpus) vs catches (fidelity scorecard); NONE where unmeasured.
- **Open tangents** — the depth TODO list: what's still worth studying here.

No pipe tables — use bullet lists or fenced/aligned blocks.

## Index

- [T1558.003 — Kerberoasting](T1558.003_kerberoasting.md) — *studying.* The session-walked tangent tree:
  RC4 vs AES vs targeted, the signal constellation (fan-out / RC4-downgrade / ticket-options / honeypot /
  tool-exec), the SPN→service-account cross-actor pivot. 17 Sigma claims; catch NONE (no local capture
  with the required fields — the data wall).
