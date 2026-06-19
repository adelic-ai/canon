"""Detection admission — the mechanism that turns a *proposed* detection (compiled from Sigma/CAR, or
LLM-authored ad-hoc) into a *committed, warranted* primitive by EVALUATING ITS CODE LOGIC AGAINST NEIGHBORS.

The **create** step is the motif IR (``from_sigma`` → a firing :class:`~detection.motif.MotifGraph`: real code,
no LLM). This module is the **evaluate** step — situate the candidate among its neighbors so its warrant is
*earned*, not assumed:

* **structural (the logic)** — clause-set relation to each neighbor: synonym / subsumed_by / subsumes /
  overlap / disjoint. Cheap, corpus-free, conservative (exact ``field|op|values`` tuples → never a
  false-claimed synonym). This is "the detection code logic evaluated against neighbors".
* **behavioral (on a labeled corpus)** — fidelity vs ground truth + *differential* coverage: what the
  candidate uniquely catches (novel), what neighbors catch that it misses (its gaps).
* **situate (optional)** — D3FEND defensive-technique context (the semantic map, not firing code): which
  defensive techniques cover the ATT&CK technique. Categorization + telemetry target, not a detector.

The returned **admission report is the candidate's content-addressed warrant**. LLM-authored is fine: the
trust comes from this deterministic evaluation, not the author (warrant-is-relational). The coverage map is
this mechanism run over a whole source corpus and tallied. (CAR is a future create-side plug-in — same
destination, a firing motif graph; no CAR data is vendored yet.)
"""

from __future__ import annotations

from dataclasses import dataclass

from detection.fidelity import _cid
from detection.motif import MotifGraph, eval_python


@dataclass(frozen=True)
class Neighbor:
    """An already-known detection to evaluate a candidate against."""

    id: str
    graph: MotifGraph


def _clause_set(g: MotifGraph) -> frozenset:
    return frozenset(m.as_tuple() for m in g.selection)


def structural_relation(candidate: MotifGraph, neighbor: MotifGraph) -> str:
    """Relation of the candidate's selection clause-set to a neighbor's. Selection is an AND, so MORE clauses
    = stricter = fires on a SUBSET of events:

    * ``synonym`` — identical clause sets;
    * ``subsumed_by`` — candidate has all the neighbor's clauses *plus more* (stricter → its matches ⊆ the
      neighbor's);
    * ``subsumes`` — candidate is a proper subset (more general → catches the neighbor's matches and more);
    * ``overlap`` — share some clauses, neither contains the other;
    * ``disjoint`` — no shared clause.

    Conservative on exact ``(field, op, values, all)`` tuples, so it never *false-claims* a synonym (different
    values ≠ synonym); behavioral fidelity is the authoritative check."""
    c, n = _clause_set(candidate), _clause_set(neighbor)
    if c == n:
        return "synonym"
    if c > n:
        return "subsumed_by"
    if c < n:
        return "subsumes"
    return "overlap" if (c & n) else "disjoint"


def _coverage(graph: MotifGraph, positives: list[dict]) -> str:
    """Belnap coverage of a detection over labeled positives: none (no ground truth) / true (all) / false
    (none) / both (some)."""
    if not positives:
        return "none"
    fired = sum(1 for p in positives if eval_python(graph, p))
    return "true" if fired == len(positives) else "false" if fired == 0 else "both"


def evaluate_against_neighbors(
    candidate: MotifGraph,
    neighbors,
    positives: list[dict],
    *,
    technique: str,
    d3fend_situation: dict | None = None,
) -> dict:
    """Evaluate a candidate detection against its neighbors and ground truth → an admission report (its
    content-addressed warrant). ``neighbors`` are :class:`Neighbor` (or ``(id, graph)`` pairs). Admit iff the
    candidate is *not* a pure synonym of a neighbor AND it earns warranted coverage (fires on ≥1 ground-truth
    instance, or catches something no neighbor does). Empty ``positives`` → no warrant earnable → not
    admitted (honest abstain, not a faked pass)."""
    neighbors = [m if isinstance(m, Neighbor) else Neighbor(*m) for m in neighbors]
    structural = [{"neighbor": m.id, "relation": structural_relation(candidate, m.graph)} for m in neighbors]
    is_synonym = any(s["relation"] == "synonym" for s in structural)

    cov = _coverage(candidate, positives)
    cand_fires = [p for p in positives if eval_python(candidate, p)]
    novel = sorted(_cid(p) for p in positives
                   if eval_python(candidate, p) and not any(eval_python(m.graph, p) for m in neighbors))
    neighbor_only = sorted(_cid(p) for p in positives
                           if not eval_python(candidate, p) and any(eval_python(m.graph, p) for m in neighbors))

    admit = (not is_synonym) and (bool(cand_fires) or bool(novel))
    reason = ("redundant — exact synonym of a neighbor" if is_synonym
              else "novel/non-redundant with warranted coverage" if admit
              else "no warranted coverage on this corpus (fires on no ground-truth instance)")

    body = {"candidate": candidate.cid, "technique": technique, "structural": structural,
            "coverage": cov, "novel": novel, "neighbor_only": neighbor_only}
    return {
        "candidate_cid": candidate.cid,
        "technique": technique,
        "structural": structural,
        "is_synonym": is_synonym,
        "fidelity": {"coverage": cov, "fired": len(cand_fires), "of": len(positives)},
        "differential": {"novel": novel, "neighbor_only": neighbor_only},
        "d3fend": d3fend_situation,
        "admit": admit,
        "reason": reason,
        "warrant_cid": _cid(body),
    }


def situate_d3fend(technique: str, *, ttl_path=None) -> dict | None:
    """Situate a detection in the D3FEND defensive ontology: the defensive techniques whose action covers the
    ATT&CK ``technique`` (the coverage target + categorization). Returns ``None`` if D3FEND / semantic_cyber
    is unavailable. D3FEND is the MAP, not firing code — it categorizes and gives telemetry context, it does
    not detect."""
    from pathlib import Path
    try:
        from semantic_cyber.d3fend import defensive_techniques_covering, load
    except ImportError:
        return None
    path = Path(ttl_path) if ttl_path else Path(__file__).parents[4] / "packages/semantic-cyber/data/d3fend.ttl"
    if not path.exists():
        return None
    g = load(str(path))
    return {"defensive_techniques": sorted(str(t) for t in defensive_techniques_covering(g, technique))}
