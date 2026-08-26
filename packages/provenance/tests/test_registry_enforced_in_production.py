"""Guard against a future accidental regression: production packages must build DAG nodes through
`derive_registered`, not raw `derive`. `derive()` itself stays permissive by design (see
`registry.py`'s module docstring — the dedup contract `test_identical_derivations_share_id` needs
it), so nothing *inside* `derive()`/`entity.py` can close the op_name/kernel gap for good. The
actual guard is that no production call site imports the unchecked primitive in the first place.
This test makes that a CI-enforced fact instead of a convention someone can silently drift from.
"""
import ast
from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]
EXEMPT_PACKAGES = {"provenance"}  # the domain-agnostic core itself owns the unchecked primitive


def _bare_derive_imports(py_file: Path) -> list[int]:
    """Line numbers where ``py_file`` imports the bare `provenance.derive` name."""
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "provenance":
            for alias in node.names:
                if alias.name == "derive":
                    hits.append(node.lineno)
    return hits


def test_no_production_package_imports_bare_derive():
    offenders = {}
    for src_dir in (REPO_ROOT / "packages").glob("*/src"):
        pkg = src_dir.parent.name
        if pkg in EXEMPT_PACKAGES:
            continue
        for py_file in src_dir.rglob("*.py"):
            hits = _bare_derive_imports(py_file)
            if hits:
                offenders[str(py_file.relative_to(REPO_ROOT))] = hits
    assert not offenders, (
        "production code importing unchecked `provenance.derive` instead of "
        f"`derive_registered` (closes the op_name/kernel collision the two provenance code "
        f"reviews on 2026-08-26 found): {offenders}"
    )
