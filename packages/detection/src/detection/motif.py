"""Detection motif IR — molecules, RDF-ization, and two *verified* emitters.

First slice of ``design/detection_ir_motif_ontology.md``. The relation is the invariant; the language
is a phrasebook. This module realizes that on the smallest instance:

* **two molecules** — :class:`FieldMatch` (a ``field|mods: spec`` clause) and :class:`Suppression`
  (a filter block, AND across clauses). The recurring composites, not single AST nodes.
* **one parser** — :func:`from_sigma` lifts an evaluable Sigma rule into a :class:`MotifGraph`
  (content-addressed by construction).
* **two emitters** — :func:`eval_python` (interpreter, reusing :mod:`detection.sigma_eval`'s primitive)
  and :func:`to_sparql`/:func:`eval_sparql` (compile the molecule-set to a SPARQL ``ASK`` over the
  event-as-RDF). Same graph, two languages.
* **the gate** — :func:`attest_emitter_agreement`: the IR is sound *iff the two emitters never disagree*
  on a corpus. "Translate to any language" is not assumed — it is fidelity-attested (a disagreement
  localizes exactly where the IR is lossy).

``rdflib`` is imported lazily inside the SPARQL/RDF functions only, so the Python emitter + parser stay
dependency-free (the ``[rdf]`` extra is needed only for the SPARQL path), mirroring
:mod:`provenance.rdf`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from provenance import evidence_digest

from detection.fidelity import _cid
from detection.sigma_eval import (
    _ascii_lower,
    field_matches,
    glob_regex_body,
    is_evaluable,
    needs_regex,
)

MOTIF = "urn:canon:motif#"        # the molecule vocabulary
MEV = "urn:canon:motif:event#"    # the event-as-RDF vocabulary (one predicate per field)

_OPS = {"endswith", "startswith", "contains"}   # string-match modifiers; anything else → equality


@dataclass(frozen=True)
class FieldMatch:
    """A ``field|mods: spec`` clause — the atom-with-a-bond. ``op`` is the match kind; ``values`` is the
    spec (a list is OR unless ``match_all`` makes it AND, the ``|all`` modifier)."""

    field: str
    op: str                       # "eq" | "contains" | "startswith" | "endswith"
    values: tuple[str, ...]
    match_all: bool               # |all → AND across values; else OR

    def as_tuple(self) -> tuple:
        return ("field_match", self.field, self.op, tuple(self.values), self.match_all)

    def _mods(self) -> set[str]:
        mods: set[str] = set()
        if self.op != "eq":
            mods.add(self.op)
        if self.match_all:
            mods.add("all")
        return mods

    def eval(self, event: dict) -> bool:
        """Evaluate against an event, reusing the proper Sigma primitive — so the Python emitter is, by
        construction, identical to :mod:`detection.sigma_eval`'s per-clause semantics."""
        return field_matches(event.get(self.field, ""), list(self.values), self._mods())


@dataclass(frozen=True)
class Suppression:
    """A filter block — AND across its clauses. The detection is suppressed if *any* suppression matches
    (Sigma's ``selection and not 1 of filter*``). The bond here is the block-level conjunction."""

    clauses: tuple[FieldMatch, ...]

    def as_tuple(self) -> tuple:
        return ("suppression", tuple(c.as_tuple() for c in self.clauses))

    def eval(self, event: dict) -> bool:
        return all(c.eval(event) for c in self.clauses)


@dataclass(frozen=True)
class MotifGraph:
    """A detection as a graph of molecules: a ``selection`` (AND of field-matches) optionally suppressed by
    filter blocks. Content-addressed by its construction (``cid``) — identical molecule-sets share a CID."""

    rule_id: str
    selection: tuple[FieldMatch, ...]
    suppressions: tuple[Suppression, ...]

    def _body(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "selection": [m.as_tuple() for m in self.selection],
            "suppressions": [s.as_tuple() for s in self.suppressions],
        }

    @property
    def cid(self) -> str:
        """Content address over the canonical molecule structure (not an RDF serialization — RDF
        canonicalization is fiddly; the structure is the identity, per the provenance discipline)."""
        return evidence_digest(json.dumps(self._body(), sort_keys=True, separators=(",", ":")))

    def fields(self) -> list[str]:
        """Every event field the graph references (selection ∪ all suppression clauses), sorted."""
        fs = {m.field for m in self.selection}
        for s in self.suppressions:
            fs |= {c.field for c in s.clauses}
        return sorted(fs)


def _parse_clause(key: str, spec) -> FieldMatch:
    field, *mods = key.split("|")
    modset = set(mods)
    op = next((m for m in modset if m in _OPS), "eq")
    values = tuple(str(v) for v in (spec if isinstance(spec, list) else [spec]))
    return FieldMatch(field=field, op=op, values=values, match_all=("all" in modset))


def from_sigma(rule: dict) -> MotifGraph:
    """Lift an evaluable Sigma rule into a motif graph (the **ingestion** — the IR's first emitter-pair
    input). Raises if the rule is outside the evaluable subset (so lossiness is loud, never silent)."""
    if not is_evaluable(rule):
        raise ValueError(f"rule {rule.get('id', '?')} is outside the evaluable Sigma subset")
    det = rule["detection"]
    selection = tuple(_parse_clause(k, v) for k, v in det["selection"].items())
    suppressions = tuple(
        Suppression(tuple(_parse_clause(k, v) for k, v in block.items()))
        for name, block in det.items()
        if name.startswith("filter") and isinstance(block, dict)
    )
    return MotifGraph(rule_id=rule.get("id", "?"), selection=selection, suppressions=suppressions)


# ── Emitter 1: Python interpreter ────────────────────────────────────────────────────────────────────

def eval_python(graph: MotifGraph, event: dict) -> bool:
    """Fire iff the selection matches and no suppression block matches — the motif graph, interpreted."""
    if not all(m.eval(event) for m in graph.selection):
        return False
    return not any(s.eval(event) for s in graph.suppressions)


# ── Emitter 2: SPARQL ASK over the event-as-RDF ──────────────────────────────────────────────────────

def _esc(s: str) -> str:
    """Escape a string for a SPARQL double-quoted literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _filter_expr(m: FieldMatch, var: str) -> str:
    """A field-match as a SPARQL boolean expression over ``var`` (the event's value for ``m.field``).

    Per value: a **wildcard** value compiles the shared :func:`~detection.sigma_eval.glob_regex_body` into an
    anchored ``REGEX(..., "s")`` — the same regex the Python oracle uses, so the two emitters glob identically
    (verified by `attest_emitter_agreement`). A **plain** value keeps the fast string function
    (``STRENDS``/``STRSTARTS``/``CONTAINS``/``=``), which is equivalent to the glob for non-wildcards. Case-fold
    is ASCII (``_ascii_lower``) on the pattern, matching the oracle; the event side's ``LCASE`` (Unicode) is the
    separate, tracked case-fold non-conformance (faithful on ASCII)."""
    fn = {"endswith": "STRENDS", "startswith": "STRSTARTS", "contains": "CONTAINS"}
    lhs = f"LCASE(STR({var}))"
    parts = []
    for v in m.values:
        p = _ascii_lower(v)
        if needs_regex(v):                                     # wildcard OR escape → compile the shared glob
            rx = "^" + glob_regex_body(p, m.op) + "$"          # anchored full match, dotall via the "s" flag
            parts.append(f'REGEX({lhs}, "{_esc(rx)}", "s")')
        else:
            lit = '"' + _esc(p) + '"'
            parts.append(f"{lhs} = {lit}" if m.op == "eq" else f"{fn[m.op]}({lhs}, {lit})")
    return "(" + (" && " if m.match_all else " || ").join(parts) + ")"


def to_sparql(graph: MotifGraph) -> str:
    """Compile the molecule-set to a SPARQL ``ASK``. The event is one node ``?e`` with one predicate per
    referenced field; the serializer (:func:`eval_sparql`) defaults absent fields to ``""`` so the two
    emitters agree on missing fields by construction."""
    var = {f: f"?f{i}" for i, f in enumerate(graph.fields())}
    lines = [f"PREFIX mev: <{MEV}>", "ASK {"]
    lines += [f"  ?e mev:{f} {var[f]} ." for f in graph.fields()]
    lines += [f"  FILTER( {_filter_expr(m, var[m.field])} )" for m in graph.selection]
    for s in graph.suppressions:                       # require NOT(block fully matches), per suppression
        inner = " && ".join(_filter_expr(c, var[c.field]) for c in s.clauses)
        lines.append(f"  FILTER( !( {inner} ) )")
    lines.append("}")
    return "\n".join(lines)


def _prepared_ask(graph: MotifGraph):
    """Parse the ``ASK`` once (parsing dominates per-event cost; reuse it across a corpus)."""
    from rdflib.plugins.sparql import prepareQuery

    return prepareQuery(to_sparql(graph))


def eval_sparql(graph: MotifGraph, event: dict, *, prepared=None) -> bool:
    """Serialize the event as RDF (absent referenced fields → ``""``) and answer the compiled ``ASK``.
    Pass ``prepared`` (from :func:`_prepared_ask`) to avoid re-parsing the query for every event."""
    import rdflib
    from rdflib import Literal, Namespace, URIRef

    g = rdflib.Graph()
    mev = Namespace(MEV)
    e = URIRef(MEV + "e")
    for f in graph.fields():
        g.add((e, mev[f], Literal(str(event.get(f, "")))))
    return bool(g.query(prepared if prepared is not None else to_sparql(graph)).askAnswer)


def to_rdf(graph: MotifGraph):
    """The IR-as-RDF view: the molecule graph as ``rdflib`` triples under the ``motif:`` vocabulary — the
    'auto-RDF-ize' artifact, queryable and content-addressed by ``graph.cid``."""
    import rdflib
    from rdflib import RDF, Literal, Namespace, URIRef

    M = Namespace(MOTIF)
    g = rdflib.Graph()
    g.bind("motif", M)
    det = URIRef(f"{MOTIF}detection:{graph.cid}")
    g.add((det, RDF.type, M.Detection))
    g.add((det, M.ruleId, Literal(graph.rule_id)))

    def add_fm(node, m: FieldMatch):
        g.add((node, RDF.type, M.FieldMatch))
        g.add((node, M.field, Literal(m.field)))
        g.add((node, M.op, Literal(m.op)))
        g.add((node, M.matchAll, Literal(m.match_all)))
        for v in m.values:
            g.add((node, M.value, Literal(v)))

    for i, m in enumerate(graph.selection):
        n = URIRef(f"{MOTIF}sel:{graph.cid}:{i}")
        g.add((det, M.selection, n))
        add_fm(n, m)
    for j, s in enumerate(graph.suppressions):
        sn = URIRef(f"{MOTIF}sup:{graph.cid}:{j}")
        g.add((det, M.suppression, sn))
        g.add((sn, RDF.type, M.Suppression))
        for k, c in enumerate(s.clauses):
            cn = URIRef(f"{MOTIF}sup:{graph.cid}:{j}:{k}")
            g.add((sn, M.clause, cn))
            add_fm(cn, c)
    return g


# ── The gate: the two emitters must agree, or the IR is lossy (localized) ─────────────────────────────

def attest_emitter_agreement(graph: MotifGraph, events: list[dict]) -> dict:
    """Run both emitters over every event. The IR is sound for this rule *iff they never disagree*.

    ``coverage='true'`` — agree on all events (the port preserved meaning) · ``coverage='false'`` — at
    least one disagreement (the IR is lossy; ``disagreements`` localizes exactly where, with each
    emitter's verdict). Content-addressed (``evidence_cid``) so the agreement claim re-derives. This is
    fidelity attestation applied *between emitters* rather than against ground truth — the warranted form
    of 'translates to any language'."""
    prepared = _prepared_ask(graph)                    # parse the ASK once, reuse across the corpus
    disagreements = [
        {"event": _cid(ev), "python": p, "sparql": s}
        for ev in events
        for p, s in [(eval_python(graph, ev), eval_sparql(graph, ev, prepared=prepared))]
        if p != s
    ]
    n = len(events)
    body = {
        "graph_cid": graph.cid,
        "n_events": n,
        "n_agree": n - len(disagreements),
        "disagreements": disagreements,
    }
    return {
        "rule": graph.rule_id,
        "emitters": ["python", "sparql"],
        "coverage": "true" if not disagreements else "false",
        "n_events": n,
        "disagreements": disagreements,
        "evidence_cid": _cid(body),
    }


# ── Step 5: the selector becomes provenance — closing the §0 hole ─────────────────────────────────────

def record_selector_provenance(path: str):
    """Record the ground-truth selector (``_comsvcs_positive``) as a ``prov:Activity`` producing the
    positive entity, so the label 'this EID10 is the malicious read' carries its own *how*: the activity's
    plan content-addresses the selector's exact source (``selector_cid``), and the corpus is an evidence
    source (CID = the file's digest). ``to_prov`` of the returned entity then emits the PROV-O derivation;
    ``.value()`` re-runs the selector. Closes the design's §0 hole (warrant-is-relational)."""
    import inspect
    from pathlib import Path

    from provenance import derive, source

    from detection.coverage_space import _comsvcs_positive
    from detection.subgraph import load_sysmon_events

    raw = Path(path).read_bytes()
    corpus = source(raw, name=f"corpus:{path}", evidence=True, kind="corpus",
                    label="OTRF LSASS corpus")
    selector_src = inspect.getsource(_comsvcs_positive)
    return derive(
        "comsvcs_positive_select",
        # params double as the prov:Plan AND kernel kwargs (interpret passes them through), so the
        # kernel accepts selector_cid even though it re-selects from the corpus rather than using it.
        kernel=lambda _bytes, selector_cid=None: _comsvcs_positive(load_sysmon_events(path)),
        used=[corpus],
        params={"selector_cid": evidence_digest(selector_src)},
        kind="ground_truth",
        label="comsvcs T1003.001 ground-truth instance",
    )
