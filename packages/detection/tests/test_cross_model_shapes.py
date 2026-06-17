"""Cross-model corroboration SHACL shape — "corroboration earned, not asserted."

A `sigma_corroboration` must be BACKED by ≥1 sigma-rule witness it actually `prov:used` — the verdict's
own provenance must exhibit the witnesses or it does not conform. Needs SHACL Advanced Features (SPARQL
target); `validate_graph` now enables them. Ships PASS/XFAIL per the shapes discipline + validates the
real emitter's output and the earned tier.
"""

from pathlib import Path

from rdflib import Graph, Literal, URIRef
from rdflib.namespace import PROV

from provenance import to_prov, validate_graph

from detection._verdict import build_detection_root, emit_detection_verdict

_SHAPES = Path(__file__).parents[3] / "contracts" / "shapes"
_SHAPE = Graph().parse(_SHAPES / "cross_model.shapes.ttl", format="turtle")
_KIND = URIRef("urn:canon:prov#kind")

CORRO = {"rules": ["proc_access_win_lsass_dump_comsvcs_dll.yml"], "votes": 1, "classes": 7,
         "technique": "T1558.003", "logsource": "windows/security"}


def _g(name: str) -> Graph:
    return Graph().parse(_SHAPES / name, format="turtle")


def test_pass_instance_conforms():
    assert validate_graph(_g("cross_model.pass.ttl"), _SHAPE).conforms


def test_xfail_instance_fails():
    # corroboration claimed (opName + votes) but no sigma-rule witness used → not earned → must fail
    assert not validate_graph(_g("cross_model.xfail.ttl"), _SHAPE).conforms


def test_real_corroborated_root_conforms():
    root = build_detection_root("kerberoast|svc_rubeus|0", {"entity": "svc_rubeus", "bin": 0}, CORRO)
    assert validate_graph(to_prov(root), _SHAPE).conforms


def test_plain_detection_conforms_vacuously():
    # no sigma_corroboration node → the shape's target is empty → conforms (it only governs corroboration)
    assert validate_graph(to_prov(build_detection_root("x", {"a": 1})), _SHAPE).conforms


def test_witness_removed_fails():
    # tamper a REAL corroborated graph: drop the prov:used edges to the sigma-rule witnesses
    root = build_detection_root("kerberoast|svc_rubeus|0", {"entity": "svc_rubeus", "bin": 0}, CORRO)
    g = to_prov(root)
    for rule in list(g.subjects(_KIND, Literal("sigma-rule"))):
        for s, p, o in list(g.triples((None, PROV.used, rule))):
            g.remove((s, p, o))
    assert not validate_graph(g, _SHAPE).conforms


def test_emitted_corroborated_verdict_still_earns_well_formed():
    # the combined shapes (generic + detection + cross_model) are satisfied by a real emit → tier earned,
    # the shape only bites on a malformed graph, never a legitimate corroboration
    v = emit_detection_verdict("kerberoast|svc_rubeus|0", technique="T1558.003", pvalue=1e-6,
                               params={"entity": "svc_rubeus", "bin": 0}, corroboration=CORRO)
    assert v.to_contract()["guarantee"]["tier"] == "well_formed"
