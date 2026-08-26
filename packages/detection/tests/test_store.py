"""Verdict store — persist a verdict and re-render it later with no live Entity, no recomputation.

Content-addressed by root CID (idempotent); the stored blob carries the render record + the PROV-O Turtle
+ the DAG DOT, so the report reproduces exactly and the graph stays queryable. Data-free toy verdict.
"""

import json
from pathlib import Path

import pytest

from detection._verdict import build_detection_root, emit_detection_verdict
from detection.render import render_report
from detection.store import (
    VerdictIntegrityError,
    find_by_tag,
    load_verdict,
    render_stored,
    save_verdict,
)
from provenance import TRUE

PARAMS = {"entity": "svc_demo", "bin": 0, "technique": "T1003.001"}
CORRO = {"rules": ["proc_access_win_lsass_dump_comsvcs_dll.yml"], "votes": 1, "classes": 7,
         "technique": "T1003.001", "logsource": "process_access"}


def _verdict_and_root():
    v = emit_detection_verdict("demo|svc_demo|0", technique="T1003.001", pvalue=1e-6, params=PARAMS,
                               who=TRUE, what=TRUE, where=TRUE, corroboration=CORRO)
    return v, build_detection_root("demo|svc_demo|0", PARAMS, CORRO)


def test_save_is_content_addressed(tmp_path):
    v, root = _verdict_and_root()
    cid = save_verdict(v, root, str(tmp_path), tag="notable:7")
    assert cid == v.to_contract()["provenance"]
    assert (tmp_path / f"{cid}.json").exists()
    # idempotent: re-saving the same verdict yields the same key, not a second file
    save_verdict(v, root, str(tmp_path), tag="notable:7")
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_stored_blob_carries_graph_and_chart(tmp_path):
    v, root = _verdict_and_root()
    cid = save_verdict(v, root, str(tmp_path), tag="notable:7")
    blob = load_verdict(cid, str(tmp_path))
    assert blob["tag"] == "notable:7"
    assert "sigma-rule:proc_access_win_lsass_dump_comsvcs_dll.yml" in blob["prov_ttl"]  # full graph kept
    assert blob["dot"].startswith("digraph verdict {")
    assert blob["record"]["corroboration"] == ["proc_access_win_lsass_dump_comsvcs_dll.yml"]


def test_render_stored_reproduces_the_live_report(tmp_path):
    v, root = _verdict_and_root()
    cid = save_verdict(v, root, str(tmp_path), tag="Notable 7")
    # the stored record re-renders identically to the live render — no Entity, no recomputation
    assert render_stored(cid, str(tmp_path)) == render_report(v, root, title="Notable 7")


def test_tampered_record_is_detected(tmp_path):
    v, root = _verdict_and_root()
    cid = save_verdict(v, root, str(tmp_path), tag="notable:7")
    path = tmp_path / f"{cid}.json"
    blob = json.loads(path.read_text())
    blob["record"]["corroboration"] = ["injected-fake-rule.yml"]  # hand-edit after save
    path.write_text(json.dumps(blob))
    with pytest.raises(VerdictIntegrityError):
        load_verdict(cid, str(tmp_path))
    with pytest.raises(VerdictIntegrityError):
        render_stored(cid, str(tmp_path))


def test_find_by_tag(tmp_path):
    v, root = _verdict_and_root()
    save_verdict(v, root, str(tmp_path), tag="notable:7")
    assert find_by_tag("notable:7", str(tmp_path)) == [v.to_contract()["provenance"]]
    assert find_by_tag("notable:nope", str(tmp_path)) == []
