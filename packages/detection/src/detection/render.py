"""Verdict renderer — project a justified verdict into a human report, a structured record, or a chart.

A pure read/format layer: it computes nothing and decides nothing. Everything it shows is already in the
verdict and its provenance DAG — :meth:`~forge_core.DetectionVerdict.to_contract` for the scalars (the
five W's + the folds), :func:`provenance.lineage` / :func:`provenance.explain` for the dependency-ordered
DAG, and the ``sigma-rule:`` entities on the corroboration edge. No correctness surface is touched; this
makes the "no result asserted that isn't shown on demand" thesis tangible rather than re-deriving it.

Three projections + a writer:
  ``render_dict``   — the structured record (machine / chart feed; the single source the others format).
  ``render_report`` — a Markdown report a human (or a Splunk-notable triage) reads.
  ``render_dot``    — a Graphviz DOT of the provenance DAG (the "chart").
  ``write_report``  — the report to a file, tagged with the source (e.g. the notable id) as metadata.

The verdict alone carries only the root CID; pass the root :class:`~provenance.Entity` (reconstructable
from the retained inputs) to render the lineage / corroboration / DAG. Without it you still get the scalars.
"""

from __future__ import annotations

from pathlib import Path

from forge_core import DetectionVerdict
from provenance import Entity, explain, lineage

_WS = ("who", "what", "when", "where", "how")


def _corroborating_rules(root: Entity) -> list[str]:
    """The external witnesses on the corroboration edge — entities labelled ``sigma-rule:<name>``."""
    return sorted(e.label.split("sigma-rule:", 1)[1]
                  for e in lineage(root)
                  if e.label and e.label.startswith("sigma-rule:"))


def render_dict(verdict: DetectionVerdict, root: Entity | None = None) -> dict:
    """The structured record — every fact the report/chart format from, in one dict. With ``root``, adds
    the corroborating rule-classes and the dependency-ordered lineage; without it, the scalars only."""
    c = verdict.to_contract()
    w = c["w_record"]
    val = c["validity"]
    validity = val.get("verdict", val) if isinstance(val, dict) else val   # show the scalar, not the raw dict
    return {
        "technique": c["technique"],
        "decision": c["decision"],
        "score": c["score"],
        "guarantee_tier": c["guarantee"]["tier"],
        "custody": c["custody"],
        "validity": validity,
        "trustworthiness": c["trustworthiness"],
        "cross_check": c.get("cross_check"),
        "w_record": {k: w[k] for k in _WS},
        "provenance_cid": c["provenance"],
        "corroboration": _corroborating_rules(root) if root is not None else [],
        "lineage": explain(root) if root is not None else None,
    }


def render_report(verdict: DetectionVerdict, root: Entity | None = None, *, title: str | None = None) -> str:
    """A Markdown report — the verdict, its W's, its folds, its external corroboration, and its lineage."""
    d = render_dict(verdict, root)
    out = [
        f"# {title or 'Detection verdict'} — {d['technique']}",
        "",
        f"**Decision:** `{d['decision']}` · **guarantee:** `{d['guarantee_tier']}` · "
        f"**score:** {d['score']:.3f}",
        "",
        "## The W's — who / what / when / where / how",
        *[f"- **{k}:** `{d['w_record'][k]}`" for k in _WS],
        "",
        "## Guarantee & trust",
        f"- tier: `{d['guarantee_tier']}`",
        f"- custody: `{d['custody']}` · validity: `{d['validity']}` · "
        f"trustworthiness: `{d['trustworthiness']}`",
        (f"- cross_check: `{d['cross_check']}`" if d["cross_check"] is not None
         else "- cross_check: _(none — no redundant-measure check ran)_"),
        "",
        "## External corroboration",
    ]
    if d["corroboration"]:
        out += [f"- ✓ `{r}`" for r in d["corroboration"]]
    else:
        out.append("- _(none recorded — independent witness absent, not refuted)_")
    if d["lineage"]:
        out += ["", "## Lineage — provenance DAG, in dependency order", "```", d["lineage"], "```"]
    out += ["", f"_provenance CID: `{d['provenance_cid']}`_"]
    return "\n".join(out)


def render_dot(root: Entity) -> str:
    """Graphviz DOT of the verdict's provenance DAG — sources as ellipses, derived nodes as boxes, edges
    are ``used`` / ``wasDerivedFrom``. Render with ``dot -Tsvg``; this is the verdict's chart."""
    out = ["digraph verdict {", "  rankdir=LR; node [shape=box,fontsize=10];"]
    for e in lineage(root):
        label = (e.label or (e.producer.op_name if e.producer else e.id[:8])).replace('"', "'")
        shape = "box" if e.producer else "ellipse"
        out.append(f'  "{e.id[:8]}" [label="{label}",shape={shape}];')
        if e.producer:
            for u in e.producer.used:
                out.append(f'  "{u.id[:8]}" -> "{e.id[:8]}";')
    out.append("}")
    return "\n".join(out)


def write_report(verdict: DetectionVerdict, root: Entity | None, path: str, *, tag: str | None = None) -> str:
    """Write :func:`render_report` to ``path``, prefixed with a metadata header tagging the ``source``
    (e.g. the Splunk notable id) and the provenance CID. Returns the path."""
    cid = verdict.to_contract()["provenance"]
    header = ["<!-- canon verdict report -->",
              f"<!-- source: {tag if tag is not None else '(untagged)'} -->",
              f"<!-- provenance_cid: {cid} -->", ""]
    Path(path).write_text("\n".join(header) + render_report(verdict, root, title=tag))
    return path
