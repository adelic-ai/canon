# contracts/shapes — SHACL well-formedness contracts

**Status:** DRAFT scaffold, 2026-05-30. Empty until shapes are authored.

SHACL shapes are the executable form of "this artifact is well-formed" — the `well-formed`
guarantee tier and the `validate` fold (architecture spine §3–4). They are authored with
the **CASE-borrowed discipline**:

- **OWL + SHACL dual-typing** — when canon authors its own op/concept classes, declare each
  as both `owl:Class` and `sh:NodeShape` (semantics + validation in one artifact).
- **PASS/XFAIL example pairs** — every shape ships a positive instance that must conform and
  a negative that must fail (the generator-validator pairing; this is canon's standard
  self-falsifying test form).

The generic structural shapes (every `prov:Activity` records its plan, etc.) already live in
the `provenance` package's `shacl.py`; domain shapes (per-op, per-concept) land here as they
are cut.
