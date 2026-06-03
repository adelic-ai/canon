"""Regime ledger — every row conforms to the contract, and the ledger's invariants hold.

The regime ledger (`design/regime_ledger.jsonl`) is the machine-readable applicability map: which
primitive beats the cheapest alternative under which condition. Schema: `contracts/regime_record.schema.json`.
This test keeps the ledger honest as it accumulates — schema-valid rows, unique ids, and the discipline
that a non-tie winner records what it `beaten` (the 'beat the marginals' record can't be empty when
something won).
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

_ROOT = Path(__file__).parents[3]
_SCHEMA = _ROOT / "contracts" / "regime_record.schema.json"
_LEDGER = _ROOT / "design" / "regime_ledger.jsonl"


def _rows() -> list[dict]:
    return [json.loads(line) for line in _LEDGER.read_text().splitlines() if line.strip()]


def test_every_row_conforms_to_the_contract():
    schema = json.loads(_SCHEMA.read_text())
    rows = _rows()
    assert len(rows) >= 6  # seeded with this session's six results
    for row in rows:
        jsonschema.validate(row, schema)


def test_ids_are_unique():
    ids = [r["id"] for r in _rows()]
    assert len(ids) == len(set(ids)), "duplicate regime ids"


def test_a_winner_records_what_it_beat():
    # the 'beat the marginals' discipline: if a primitive won (not a tie/none), it must name what it beat.
    for r in _rows():
        if r["winner"] not in ("tie", "none"):
            assert r["beaten"], f"{r['id']}: a winner must record what it beat"


def test_hypothesized_rows_are_marked_not_validated():
    # an untested expected regime must not masquerade as evidence (the None-vs-False discipline).
    for r in _rows():
        if r["evidence_tier"] == "hypothesized":
            assert r["label_quality"] == "none"
            assert "untested" in json.dumps(r).lower() or "hypothes" in json.dumps(r).lower()
