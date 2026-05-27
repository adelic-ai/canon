"""Smoke tests — scaffold importability + Protocol shape."""

from __future__ import annotations


def test_package_imports():
    import semantic_core

    assert semantic_core.__version__ == "0.0.1"


def test_protocols_exposed():
    from semantic_core.protocols import Bridge, ConceptId, FrameworkAdapter, Lattice

    assert ConceptId is str
    assert hasattr(Lattice, "elements")
    assert hasattr(Bridge, "map")
    assert hasattr(FrameworkAdapter, "load")


def test_submodules_importable():
    from semantic_core import bridges, fca, graph, reasoning, validation  # noqa: F401
