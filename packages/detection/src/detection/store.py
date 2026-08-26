"""Verdict store — persist a justified verdict so it can be looked up and re-rendered later.

A bare verdict carries only its root CID; the provenance DAG is reconstructable from the retained inputs,
but re-deriving it means re-running the detector. The store closes that gap by serializing, at save time,
the structured render record (:func:`detection.render.render_dict` — scalars + W's + folds + corroboration
+ lineage text) **and** the full PROV-O graph (Turtle), so a stored verdict re-renders — and stays
SPARQL-queryable — with no live Entity and no recomputation.

Content-addressed by the root CID: the filename *is* the verdict's identity, so the same verdict saves to
the same file (idempotent, dedup-by-construction — the same discipline as the DAG it records). ``tag``
(e.g. a Splunk notable id) is queryable metadata, not identity. Retention is the caller's policy: point
``store_dir`` at a tmp dir for ephemeral triage or a durable path for kept evidence — the store does not
decide lifetime.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from forge_core import DetectionVerdict
from provenance import Entity, to_prov

from detection.render import render_dict, report_from_dict, render_dot

_DIGESTED_FIELDS = ("cid", "tag", "record", "prov_ttl", "dot")


class VerdictIntegrityError(ValueError):
    """Raised when a stored verdict's contents don't match its recorded digest — the file was
    edited (by hand or otherwise) after :func:`save_verdict` wrote it. The root CID identifies the
    *computation recipe*, not the serialized store object, so it can't catch this on its own — this
    digest is what actually binds the envelope."""


def _record_digest(blob: dict) -> str:
    body = json.dumps({k: blob[k] for k in _DIGESTED_FIELDS}, sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def save_verdict(verdict: DetectionVerdict, root: Entity | None, store_dir: str, *,
                 tag: str | None = None) -> str:
    """Persist ``verdict`` (+ its ``root`` for lineage/graph) under ``store_dir``, keyed by the root CID.
    Returns the CID. Writes ``{store_dir}/{cid}.json`` holding the render record, the PROV-O Turtle, the
    DAG DOT, the ``tag``, and a ``record_digest`` binding all of them together (see :func:`load_verdict`).
    Idempotent: re-saving the same verdict overwrites the same file."""
    cid = verdict.to_contract()["provenance"]
    blob = {
        "cid": cid,
        "tag": tag,
        "record": render_dict(verdict, root),                                  # re-renders the report
        "prov_ttl": to_prov(root).serialize(format="turtle") if root is not None else None,
        "dot": render_dot(root) if root is not None else None,                 # the chart
    }
    blob["record_digest"] = _record_digest(blob)
    d = Path(store_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{cid}.json").write_text(json.dumps(blob, indent=2))
    return cid


def load_verdict(cid: str, store_dir: str) -> dict:
    """Load the stored blob for ``cid`` (``{cid, tag, record, prov_ttl, dot, record_digest}``).
    Raises :class:`VerdictIntegrityError` if the loaded fields don't match ``record_digest`` — the
    file was modified since :func:`save_verdict` wrote it."""
    blob = json.loads((Path(store_dir) / f"{cid}.json").read_text())
    if _record_digest(blob) != blob.get("record_digest"):
        raise VerdictIntegrityError(
            f"stored verdict {cid!r} in {store_dir!r} failed its integrity check — "
            "the file was modified after save_verdict wrote it"
        )
    return blob


def render_stored(cid: str, store_dir: str, *, title: str | None = None) -> str:
    """Re-render the Markdown report for a stored verdict — no live Entity, no recomputation. Defaults the
    report title to the stored ``tag``."""
    blob = load_verdict(cid, store_dir)
    return report_from_dict(blob["record"], title=title if title is not None else blob.get("tag"))


def find_by_tag(tag: str, store_dir: str) -> list[str]:
    """The CIDs of stored verdicts carrying ``tag`` (e.g. all verdicts for one notable). Sorted."""
    out = []
    for p in Path(store_dir).glob("*.json"):
        try:
            if json.loads(p.read_text()).get("tag") == tag:
                out.append(p.stem)
        except (json.JSONDecodeError, OSError):
            pass
    return sorted(out)
