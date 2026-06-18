"""Workspace — the per-engagement case file canon points at and writes back into.

First slice of ``design/engine_workspace_boundary.md``. The engine carries no set-specific state; a
:class:`Workspace` binds the data **sources** + the ruleset **pin** + the **derived**/**parameters** stores
(subdirs of the workspace root). canon reads sources + ruleset *from* a workspace and writes its findings
*into* the derived store — so the same engine runs against a swappable workspace, and a re-run with a changed
ruleset pin diffs against the prior derived artifacts.

Design boundary made literal: the corpus path and ruleset root are no longer baked into the flow; they come
from the workspace. Point the engine at another workspace and it runs there, unchanged.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from detection.baseline import blend_baselines, credibility_estimates, learn_entity_baseline
from detection.coverage_space import LocationCoverage, lsass_location_coverage
from detection.fidelity import _cid


@dataclass(frozen=True)
class Source:
    """A data source the engine is pointed at — a *reference*, not the bytes (unless small). ``kind`` is the
    telemetry family (``sysmon`` / ``kerberos`` / …); ``retention_window`` feeds the fragmentation coverage
    staircase; ``cid`` content-addresses the bytes when known."""

    ref: str
    kind: str
    retention_window: str | None = None
    cid: str | None = None


@dataclass(frozen=True)
class Ruleset:
    """The ruleset the detections were evaluated against — a *pin*, so a re-run with a different pin is a
    different, diffable derivation."""

    corpus_ref: str          # path to the Sigma rules root
    version: str             # a version tag or CID


@dataclass(frozen=True)
class Workspace:
    """A per-engagement case file: sources + ruleset pin + (by convention) ``derived/`` and ``parameters/``
    stores under ``root``. Self-describing via ``workspace.json``; the engine holds none of this."""

    root: str
    sources: tuple[Source, ...]
    ruleset: Ruleset
    recipes: tuple[str, ...] = ()        # dataset-generator recipe CIDs for any synthetic data mixed in

    @property
    def derived_dir(self) -> str:
        return str(Path(self.root) / "derived")

    @property
    def parameters_dir(self) -> str:
        return str(Path(self.root) / "parameters")

    def source_of(self, kind: str) -> Source | None:
        return next((s for s in self.sources if s.kind == kind), None)

    def sigma_root(self) -> Path:
        return Path(self.ruleset.corpus_ref)

    def save(self) -> str:
        """Write the manifest to ``{root}/workspace.json`` (derived/parameters are subdirs, created on use)."""
        d = Path(self.root)
        d.mkdir(parents=True, exist_ok=True)
        manifest = {
            "sources": [asdict(s) for s in self.sources],
            "ruleset": asdict(self.ruleset),
            "recipes": list(self.recipes),
        }
        path = d / "workspace.json"
        path.write_text(json.dumps(manifest, indent=2))
        return str(path)

    @classmethod
    def load(cls, root: str) -> "Workspace":
        m = json.loads((Path(root) / "workspace.json").read_text())
        return cls(
            root=root,
            sources=tuple(Source(**s) for s in m["sources"]),
            ruleset=Ruleset(**m["ruleset"]),
            recipes=tuple(m.get("recipes", ())),
        )


def run_lsass_location_coverage(ws: Workspace) -> tuple[LocationCoverage, str]:
    """Run the location-coverage flow against a workspace: corpus + ruleset come *from* ``ws``, the derived
    artifact is written *into* ``ws.derived_dir`` (content-addressed). Returns ``(coverage, derived_cid)``.

    The engine holds no path of its own — point it at another workspace and it runs there, unchanged. The
    written artifact records the ruleset pin alongside the result, so a re-run with a different pin produces a
    different CID that :func:`diff_derived` can compare against the prior one."""
    sysmon = ws.source_of("sysmon")
    if sysmon is None:
        raise ValueError("workspace has no 'sysmon' source")
    cov = lsass_location_coverage(sysmon.ref, sigma_root=ws.sigma_root())
    artifact = {
        "kind": "location_coverage",
        "technique": cov.technique,
        "corpus": sysmon.ref,
        "ruleset": asdict(ws.ruleset),
        "verdict": cov.verdict.to_contract(),
        "witnesses": [dict(w) for w in cov.witnesses],
        "gaps": [dict(g) for g in cov.gaps],
    }
    cid = _cid(artifact)
    d = Path(ws.derived_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{cid}.json").write_text(json.dumps(artifact, indent=2))
    return cov, cid


def load_derived(ws: Workspace, cid: str) -> dict:
    """Load a derived artifact by CID from the workspace's derived store."""
    return json.loads((Path(ws.derived_dir) / f"{cid}.json").read_text())


def diff_derived(prior: dict, rerun: dict) -> dict:
    """Diff two location-coverage artifacts (e.g. a re-run with a changed ruleset pin). The verdict is the
    stable structural primary; what moves is *coverage* — which witness rules fired, which gaps appeared.
    This is the re-analysis story made concrete: re-derive, then diff against the prior derivation."""
    def names(art: dict, key: str) -> set[str]:
        return {x["rule"] for x in art.get(key, [])}

    return {
        "verdict_changed": prior.get("verdict") != rerun.get("verdict"),
        "ruleset_prior": prior.get("ruleset"),
        "ruleset_rerun": rerun.get("ruleset"),
        "witnesses_added": sorted(names(rerun, "witnesses") - names(prior, "witnesses")),
        "witnesses_removed": sorted(names(prior, "witnesses") - names(rerun, "witnesses")),
        "gaps_added": sorted(names(rerun, "gaps") - names(prior, "gaps")),
        "gaps_removed": sorted(names(prior, "gaps") - names(rerun, "gaps")),
    }


# ── The parameters store: named, mutable, accumulating learned state ──────────────────────────────────
# Distinct from the derived store on purpose: ``derived/`` holds immutable, CID-keyed *findings* (a verdict
# is what it is); ``parameters/`` holds named, mutable, *accumulating* learned state (a baseline grows as the
# engine is re-run over more data). Findings are addressed by content; parameters by name.

def save_parameter(ws: Workspace, name: str, payload: dict) -> str:
    """Persist a named learned parameter into ``ws.parameters_dir`` (overwriting the prior — parameters
    accumulate by being *re-blended*, not by piling up files). Returns the path."""
    d = Path(ws.parameters_dir)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}.json"
    p.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return str(p)


def load_parameter(ws: Workspace, name: str) -> dict | None:
    """Load a named learned parameter, or ``None`` if the workspace has never learned it (first run)."""
    p = Path(ws.parameters_dir) / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def _load_events(source: Source) -> list[dict]:
    """Load a source's events: a ``sysmon`` source via the Sysmon loader, else a ``json`` file holding a list
    of event dicts (the generic case)."""
    if source.kind == "sysmon":
        from detection.subgraph import load_sysmon_events
        return load_sysmon_events(source.ref)
    return json.loads(Path(source.ref).read_text())


def update_entity_baseline(ws: Workspace, *, entity: str, value: str,
                           source_kind: str = "json", name: str = "entity_baseline") -> dict:
    """Learn/extend a per-entity baseline from the workspace's corpus and persist it into the parameters
    store. **Algorithm in canon, learned values in the workspace**: this loads the prior baseline from
    ``ws`` (``None`` on first run), learns from ``ws``'s source, *blends* (additively — the parameter grows),
    and writes it back. On a re-run over more data the entity's ``n`` rises and its credibility ``Z`` with it,
    sharpening the estimate toward the entity's own mean. Returns ``{first_run, baseline, estimates}``."""
    src = ws.source_of(source_kind)
    if src is None:
        raise ValueError(f"workspace has no '{source_kind}' source")
    observed = learn_entity_baseline(_load_events(src), entity=entity, value=value)
    prior = load_parameter(ws, name)
    updated = blend_baselines(prior, observed)
    save_parameter(ws, name, updated)
    return {"first_run": prior is None, "baseline": updated,
            "estimates": credibility_estimates(updated)}
