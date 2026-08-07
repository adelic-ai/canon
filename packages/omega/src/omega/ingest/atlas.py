"""The ATLAS adapter — MITRE ATLAS, omega's **spine** ingest (not a rule adapter).

Unlike Sigma/CAR (rule corpora, lowered to :class:`~omega.ir.CompiledRule`), ATLAS is a taxonomy —
like ATT&CK, it is a spine other corpora get mapped *onto*, not a set of detections. So this adapter
lowers to :class:`~omega.ir.AtlasTechnique`, the spine-node IR (ATLAS-SPEC.md §1/§3.1), and the
contract is the same shape as the rule adapters' entry point — ``load_ir(root) -> (list[...], ParseReport)``
— minus the rule-specific baggage.

Source: the compiled ``dist/ATLAS.yaml`` (public, no scrub needed — ATLAS-SPEC.md §2). Its top-level
shape is ``{..., matrices: [{tactics: [...], techniques: [...], mitigations: [...]}], case-studies: [...]}``.
This adapter reads ``matrices[0].tactics`` and ``matrices[0].techniques`` — the two collections the
coverage cartography needs (technique id/name/tactic/subtechnique-parentage/ATT&CK-reference).
Mitigations and case studies carry no coverage-relevant fields and are not ingested (out of scope for
§3.3's coverage table).

A technique's ATT&CK cross-reference — ``ATT&CK-reference: {id: T1596, ...}`` — is the one field that
makes the bridge possible; most ATLAS techniques (the AI-native ones) simply lack it, and that absence
is itself the signal the coverage classifier reads (ATLAS-SPEC.md §4).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from omega.ingest.base import ParseReport
from omega.ir import AtlasTechnique, Source

__all__ = ["to_ir", "load_ir"]


def _attack_ref(technique: dict) -> tuple[str, ...]:
    """``ATT&CK-reference: {id: T1596, ...}`` -> Sigma-tag-format ATT&CK ids (``attack.t1596``), so they
    compare directly against a rule's ``attack``-axis tokens. 0 or 1 today (ATLAS references at most one
    ATT&CK technique per node) — a tuple regardless, so a future multi-reference doesn't change the shape."""
    ref = technique.get("ATT&CK-reference")
    if not ref or not ref.get("id"):
        return ()
    return (f"attack.{str(ref['id']).lower()}",)


def to_ir(technique: dict, *, path: str | Path | None = None) -> AtlasTechnique:
    """Map one parsed ATLAS technique dict -> :class:`~omega.ir.AtlasTechnique`. Total by construction — it
    only reads fields, every technique object maps. A subtechnique carries ``specializes`` (the parent
    technique id) instead of its own ``tactics`` list; the parent's tactics are NOT inherited here — an
    explicit choice, recorded in DECISIONS.md."""
    tid = technique["id"]
    return AtlasTechnique(
        id=tid,
        name=technique.get("name", ""),
        tactics=tuple(technique.get("tactics") or ()),
        parent=technique.get("specializes"),
        attack_refs=_attack_ref(technique),
        source=Source("atlas", native_id=tid, path=str(path) if path else None),
    )


def _locate(root: Path) -> Path:
    """Resolve ``root`` to the compiled ``ATLAS.yaml``: accept the file itself, or a checkout/``dist``
    directory to search (ATLAS-SPEC.md §2 prefers ``dist/ATLAS.yaml``)."""
    if root.is_file():
        return root
    for candidate in (root / "dist" / "ATLAS.yaml", root / "ATLAS.yaml"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"omega ATLAS ingest: no ATLAS.yaml found under {root} (looked in dist/ and root)")


def load_ir(root: str | Path) -> tuple[list[AtlasTechnique], ParseReport]:
    """The ATLAS adapter's contract entry point: parse the compiled ATLAS.yaml under/at ``root`` into the
    spine IR plus a :class:`ParseReport`. ``report.rules`` counts spine nodes (techniques + subtechniques),
    matching the rule adapters' field name even though these aren't rules — the same "how much did this
    ingest total up" accounting. Non-technique matrix members (tactics, mitigations) are not spine nodes and
    are not counted here."""
    root = Path(root)
    path = _locate(root)
    report = ParseReport()
    report.files = 1
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        report.record_error(path, exc)
        return [], report

    matrices = (doc or {}).get("matrices") or []
    if not matrices:
        report.defer("no-matrices")
        return [], report

    techniques: list[AtlasTechnique] = []
    for matrix in matrices:
        for technique in matrix.get("techniques") or []:
            if technique.get("object-type") not in (None, "technique"):
                report.defer("non-technique")
                continue
            if "id" not in technique:
                report.defer("missing-id")
                continue
            techniques.append(to_ir(technique, path=path))
            report.rules += 1
    return techniques, report
