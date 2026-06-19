"""Recipe + content-address for a synthetic corpus — reproducible, citable artifacts.

``recipe_cid`` content-addresses a scenario set by its canonical JSON, so the same scenarios re-derive the same
CID: a generated corpus is referable by ``cid:…`` rather than being an opaque blob. ``compose`` merges scenario
lists into one corpus. Dependency-free (stdlib ``hashlib``/``json``) — the generator stays canon-free.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass


def _canon(obj):
    if is_dataclass(obj) and not isinstance(obj, type):
        return _canon(asdict(obj))
    if isinstance(obj, dict):
        return {k: _canon(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_canon(v) for v in obj]
    return obj


def recipe_cid(scenarios) -> str:
    """sha2-256 over the canonical JSON of a scenario set — same scenarios → same CID (reproducible artifact)."""
    blob = json.dumps(_canon(list(scenarios)), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def compose(*scenario_lists):
    """Merge scenario lists into one corpus."""
    return [s for lst in scenario_lists for s in lst]
