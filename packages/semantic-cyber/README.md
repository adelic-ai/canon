# semantic-cyber

Cyber domain ontology adapters. Adopts D3FEND as the defensive knowledge graph and ATT&CK as the offensive one; bridges Sigma/CAR/OCSF to those at curation time.

## What this package does

- **D3FEND loader** — parses local `d3fend.ttl` into a semantic-core `Graph`. Local file (re-fetchable from d3fend.mitre.org) avoids API runtime dependency per canon architecture.
- **Local counter derivation** — replicates the d3fend.mitre.org API's defensive-counters-offensive logic via SPARQL over OWL restrictions: defensive techniques that act on the same artifact an offensive technique produces/uses.
- *Future:* ATT&CK STIX loader, framework bridges (Sigma↔D3FEND, CAR↔D3FEND, OCSF↔ATT&CK), SHACL shapes, migration of TASC catalog data.

## Fetching D3FEND

```
uv run --package semantic-cyber python scripts/fetch_d3fend.py
```

Downloads to `data/d3fend.ttl` (gitignored). Re-run when MITRE publishes updates.
