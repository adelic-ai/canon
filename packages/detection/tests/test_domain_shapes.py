"""Domain SHACL shapes — the detection op-plan shape (PASS/XFAIL discipline).

The first per-op shape in `contracts/shapes/` (the dir was README-only). It requires a recorded
op-plan to carry its `canon:params` — the re-derivable recipe — stricter than the generic PROV-O
well-formedness. Per the shapes discipline, the shape ships a PASS instance (must conform) and an
XFAIL instance (must fail); we also validate a real detection root.
"""

from pathlib import Path

from rdflib import Graph

from provenance import to_prov, validate_graph

from detection._verdict import build_detection_root

_SHAPES = Path(__file__).parents[3] / "contracts" / "shapes"


def _g(name: str) -> Graph:
    g = Graph()
    g.parse(_SHAPES / name, format="turtle")
    return g


_SHAPE = _g("detection.shapes.ttl")


def test_pass_instance_conforms():
    assert validate_graph(_g("detection.pass.ttl"), _SHAPE).conforms


def test_xfail_instance_fails():
    # an op-plan with opName but no params is not re-derivable → must fail the shape
    assert not validate_graph(_g("detection.xfail.ttl"), _SHAPE).conforms


def test_real_detection_root_conforms():
    root = build_detection_root("cloudtrail-region-sweep|backup",
                                {"entity": "backup", "technique": "T1496"})
    assert validate_graph(to_prov(root), _SHAPE).conforms
