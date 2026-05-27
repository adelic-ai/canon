"""bridges.py — cross-framework SKOS bridges."""

from __future__ import annotations

import pytest

from semantic_core.bridges import (
    DictBridge,
    bridges_from_graph,
    compose,
    invert,
)
from semantic_core.graph import Graph
from semantic_core.protocols import Bridge


SIGMA_SCHEME = "https://sigma.example/"
DFND_SCHEME = "https://d3fend.mitre.org/"
ATT_SCHEME = "https://attack.mitre.org/"


def test_dictbridge_satisfies_bridge_protocol():
    b = DictBridge(SIGMA_SCHEME, DFND_SCHEME, {f"{SIGMA_SCHEME}rule_a": [f"{DFND_SCHEME}cap_x"]})
    assert isinstance(b, Bridge)


def test_dictbridge_map_returns_targets():
    b = DictBridge(
        SIGMA_SCHEME,
        DFND_SCHEME,
        {
            f"{SIGMA_SCHEME}rule_a": [f"{DFND_SCHEME}cap_x", f"{DFND_SCHEME}cap_y"],
            f"{SIGMA_SCHEME}rule_b": [f"{DFND_SCHEME}cap_z"],
        },
    )
    assert set(b.map(f"{SIGMA_SCHEME}rule_a")) == {f"{DFND_SCHEME}cap_x", f"{DFND_SCHEME}cap_y"}
    assert tuple(b.map(f"{SIGMA_SCHEME}unknown")) == ()


def test_compose_chains_bridges():
    sigma_dfnd = DictBridge(
        SIGMA_SCHEME, DFND_SCHEME, {f"{SIGMA_SCHEME}r1": [f"{DFND_SCHEME}c1"]}
    )
    dfnd_att = DictBridge(
        DFND_SCHEME, ATT_SCHEME, {f"{DFND_SCHEME}c1": [f"{ATT_SCHEME}T1558"]}
    )
    sigma_att = compose(sigma_dfnd, dfnd_att)
    assert sigma_att.source_scheme == SIGMA_SCHEME
    assert sigma_att.target_scheme == ATT_SCHEME
    assert tuple(sigma_att.map(f"{SIGMA_SCHEME}r1")) == (f"{ATT_SCHEME}T1558",)


def test_compose_rejects_mismatched_schemes():
    a = DictBridge(SIGMA_SCHEME, DFND_SCHEME)
    b = DictBridge(SIGMA_SCHEME, ATT_SCHEME)
    with pytest.raises(ValueError, match="cannot compose"):
        compose(a, b)


def test_compose_handles_one_to_many():
    a = DictBridge(
        SIGMA_SCHEME, DFND_SCHEME, {f"{SIGMA_SCHEME}r": [f"{DFND_SCHEME}c1", f"{DFND_SCHEME}c2"]}
    )
    b = DictBridge(
        DFND_SCHEME,
        ATT_SCHEME,
        {f"{DFND_SCHEME}c1": [f"{ATT_SCHEME}T1"], f"{DFND_SCHEME}c2": [f"{ATT_SCHEME}T2"]},
    )
    composed = compose(a, b)
    assert set(composed.map(f"{SIGMA_SCHEME}r")) == {f"{ATT_SCHEME}T1", f"{ATT_SCHEME}T2"}


def test_invert_reverses_direction():
    b = DictBridge(
        SIGMA_SCHEME,
        DFND_SCHEME,
        {f"{SIGMA_SCHEME}r1": [f"{DFND_SCHEME}c1"], f"{SIGMA_SCHEME}r2": [f"{DFND_SCHEME}c1"]},
    )
    inv = invert(b)
    assert inv.source_scheme == DFND_SCHEME
    assert inv.target_scheme == SIGMA_SCHEME
    assert set(inv.map(f"{DFND_SCHEME}c1")) == {f"{SIGMA_SCHEME}r1", f"{SIGMA_SCHEME}r2"}


SKOS_TURTLE = f"""
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
@prefix sigma: <{SIGMA_SCHEME}> .
@prefix dfnd: <{DFND_SCHEME}> .

sigma:rule_a skos:exactMatch dfnd:cap_x .
sigma:rule_b skos:closeMatch dfnd:cap_y .
"""


def test_bridges_from_graph_extracts_exact_and_close_match():
    g = Graph().load_turtle(SKOS_TURTLE)
    bridge = bridges_from_graph(g, SIGMA_SCHEME, DFND_SCHEME)
    assert tuple(bridge.map(f"{SIGMA_SCHEME}rule_a")) == (f"{DFND_SCHEME}cap_x",)
    assert tuple(bridge.map(f"{SIGMA_SCHEME}rule_b")) == (f"{DFND_SCHEME}cap_y",)


def test_bridges_from_graph_handles_reversed_triple_direction():
    """skos:exactMatch is symmetric; the curator may have stated it in either direction."""
    reversed_ttl = f"""
    @prefix skos: <http://www.w3.org/2004/02/skos/core#> .
    @prefix sigma: <{SIGMA_SCHEME}> .
    @prefix dfnd: <{DFND_SCHEME}> .

    dfnd:cap_x skos:exactMatch sigma:rule_a .
    """
    g = Graph().load_turtle(reversed_ttl)
    bridge = bridges_from_graph(g, SIGMA_SCHEME, DFND_SCHEME)
    assert tuple(bridge.map(f"{SIGMA_SCHEME}rule_a")) == (f"{DFND_SCHEME}cap_x",)
