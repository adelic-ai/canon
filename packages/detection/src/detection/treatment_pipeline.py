"""The detection-treatment recipe + manifest — stage 0 of the pipeline made provenance-tracked.

`design/sigma_treatment_pipeline.md` formalizes consuming a rule corpus as a fixed, content-addressed
pipeline; this is the orchestration that makes a run **reproducible** and **ablatable**. `treat(rules,
techniques)` runs the corpus-derivable stages — ingest/pin → compile→IR → categorize (the SKOS lattice) —
content-addresses each, and emits a :class:`Manifest` pinning the inputs to a single ``result_cid``:

- **Reproducible** — same rules + techniques (+ same code) → the *same* ``result_cid``. The end-result knows
  the state that produced it.
- **Ablatable** — change one stage (a rule, a better lattice metric) → that stage's CID changes → the
  ``result_cid`` changes, and :func:`diff_manifests` localizes *which* stage moved. That diff-the-result loop
  is the ML-ish experiment loop with provenance instead of vibes.

Honest scope: the **event/label-gated** stages — ``verify_with_events`` (faithful firing needs events) and
``ground`` (catch-set needs labels) — are recorded as ``None`` (not run), never faked. The manifest carries
its own incompleteness. Source-agnostic: Sigma now; CAR/SPL/KQL enter at ``compile`` as alternate frontends.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass

from provenance import evidence_digest

from detection.coverage import coverage_report
from detection.rule_ir import compile_rule
from detection.rule_lattice import build_lattice
from detection.sigma_eval import is_evaluable

RECIPE = "detection-treatment@v1"


def _cid(obj) -> str:
    """Content-address any JSON-able value (canonical serialization → digest)."""
    return evidence_digest(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str))


def current_commit() -> str | None:
    """The repo's HEAD commit, for the manifest's code pin — ``None`` if not in a git repo."""
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


@dataclass(frozen=True)
class Manifest:
    """The provenance pin of one treatment run: the inputs (corpus, code, techniques), the per-stage content
    addresses, and the single ``result_cid`` they roll up to. Same manifest ⇒ same ``result_cid``."""

    recipe: str
    techniques: tuple
    code_commit: str | None
    corpus_cid: str
    stage_cids: dict          # {stage: cid | None}; None = an event/label-gated stage not run
    result_cid: str

    def to_dict(self) -> dict:
        return asdict(self)


def treat(rules: list[dict], techniques, *, code_commit: str | None = None) -> dict:
    """Run the corpus-derivable treatment stages over ``rules`` (raw Sigma dicts) for ``techniques`` and
    return the content-addressed result + its :class:`Manifest`. Non-evaluable rules are dropped at ingest."""
    evaluable = [r for r in rules if isinstance(r, dict) and is_evaluable(r)]

    # stage 0 — ingest + pin: the identity+logic of the ingested rules (pre-compile, syntax-stable)
    corpus_cid = _cid(sorted((r.get("id", "?"), r.get("detection")) for r in evaluable))
    # stage 1 — compile → IR: the typed firing logic (each rule's content-addressed IR)
    compiled = [compile_rule(r) for r in evaluable]
    compile_cid = _cid(sorted(ir.cid for ir in compiled))
    # stage 3 — categorize: the SKOS-graded relation lattice (edges incl. tightness)
    lattice = build_lattice(compiled)
    categorize_cid = _cid({"counts": lattice["counts"],
                           "edges": sorted([a, rel, b, t] for a, rel, b, *rest in lattice["edges"]
                                           for t in [rest[0] if rest else None])})
    # stage 5 — coverage: per-TTP structural layer report (primitive/atom/rule/concept; gaps=NONE)
    coverage = coverage_report(evaluable, compiled, lattice, techniques)
    coverage_cid = _cid(coverage)

    stage_cids = {
        "ingest": corpus_cid,
        "compile": compile_cid,
        "verify_with_events": None,     # gated: faithful firing needs events (attest_ir_faithful)
        "categorize": categorize_cid,
        "ground": None,                 # gated: catch-set needs labels (stage 4, Maude's lane)
        "coverage": coverage_cid,       # corpus-derivable: structural per-TTP layers (catch-class deferred)
    }
    result_cid = _cid({k: v for k, v in stage_cids.items() if v is not None})
    manifest = Manifest(RECIPE, tuple(sorted(techniques)), code_commit, corpus_cid, stage_cids, result_cid)
    return {"manifest": manifest, "lattice": lattice, "coverage": coverage, "n_evaluable": len(compiled)}


def diff_manifests(a: Manifest, b: Manifest) -> dict:
    """Which stages moved between two runs — the ablation localizer. ``changed`` lists the stages whose CID
    differs (and thus what made the ``result_cid`` change); ``same_result`` is True iff the runs are
    identical end-to-end (reproducibility check)."""
    changed = [s for s in a.stage_cids
               if a.stage_cids.get(s) != b.stage_cids.get(s)]
    return {"changed_stages": changed,
            "result_changed": a.result_cid != b.result_cid,
            "same_result": a.result_cid == b.result_cid}
