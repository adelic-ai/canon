"""Verdict renderer — pure projection over an already-justified verdict + its provenance DAG.

No data dependency: a toy verdict (with a corroboration edge) exercises every projection. The renderer
computes nothing — it only reads to_contract + lineage/explain — so these assertions are about faithful
*presentation*, not detection logic.
"""

import json

from detection._verdict import build_detection_root, emit_detection_verdict
from detection.render import render_dict, render_dot, render_report, write_report
from provenance import TRUE

PARAMS = {"entity": "svc_demo", "bin": 0, "technique": "T1003.001"}
CORRO = {"rules": ["proc_access_win_lsass_dump_comsvcs_dll.yml"], "votes": 1, "classes": 7,
         "technique": "T1003.001", "logsource": "process_access"}


def _verdict_and_root():
    v = emit_detection_verdict("demo|svc_demo|0", technique="T1003.001", pvalue=1e-6, params=PARAMS,
                               who=TRUE, what=TRUE, where=TRUE, corroboration=CORRO)
    root = build_detection_root("demo|svc_demo|0", PARAMS, CORRO)
    return v, root


def test_dict_carries_every_fact():
    v, root = _verdict_and_root()
    d = render_dict(v, root)
    assert d["technique"] == "T1003.001" and d["decision"] == "true"
    assert d["guarantee_tier"] == "well_formed"
    assert set(d["w_record"]) == {"who", "what", "when", "where", "how"}
    assert d["corroboration"] == ["proc_access_win_lsass_dump_comsvcs_dll.yml"]   # from the provenance edge
    assert d["lineage"] and isinstance(d["lineage"], str)
    json.dumps(d)   # the structured record is serializable (chart/feed-ready)


def test_report_is_human_readable_and_complete():
    v, root = _verdict_and_root()
    r = render_report(v, root, title="Notable 42")
    for must in ("Notable 42", "T1003.001", "true", "well_formed", "who", "comsvcs", "Lineage"):
        assert must in r


def test_dot_is_a_dag_of_the_provenance():
    v, root = _verdict_and_root()
    dot = render_dot(root)
    assert dot.startswith("digraph verdict {") and dot.rstrip().endswith("}")
    assert "->" in dot                              # at least one derived-from edge


def test_scalars_render_without_a_root():
    v, _ = _verdict_and_root()
    d = render_dict(v)                              # no root → scalars only, no lineage/corroboration
    assert d["technique"] == "T1003.001"
    assert d["corroboration"] == [] and d["lineage"] is None


def test_write_report_tags_the_source(tmp_path):
    v, root = _verdict_and_root()
    p = write_report(v, root, str(tmp_path / "verdict.md"), tag="notable:42")
    text = open(p).read()
    assert "source: notable:42" in text             # tagged with the notable id as metadata
    assert "provenance_cid:" in text and "T1003.001" in text
