"""Real CID conformance — `contracts/cid.md` PIN 2 (canonical DAG-CBOR, self-describing CIDv1)."""
import subprocess
import sys

from provenance.cid import canonical_encode, cid_from_bytes, recipe_cid


def test_param_order_does_not_affect_cid():
    a = recipe_cid("op", {"a": 1, "b": 2}, ())
    b = recipe_cid("op", {"b": 2, "a": 1}, ())
    assert a == b


def test_int_and_float_are_distinct():
    assert recipe_cid("op", {"x": 1}, ()) != recipe_cid("op", {"x": 1.0}, ())


def test_different_op_names_differ():
    assert recipe_cid("a", {}, ()) != recipe_cid("b", {}, ())


def test_different_parents_differ():
    assert recipe_cid("op", {}, ("p1",)) != recipe_cid("op", {}, ("p2",))


def test_cid_is_self_describing_dag_cbor_sha256():
    cid = recipe_cid("op", {}, ())
    assert cid.startswith("b")  # multibase: base32, lowercase, no padding
    # decode the multibase/CIDv1/multicodec/multihash header and confirm it names
    # CIDv1 + dag-cbor + sha2-256, per PIN 2 — the property the old truncated-hex
    # scheme had no way to express.
    padded = cid[1:] + "=" * ((8 - len(cid[1:]) % 8) % 8)
    import base64

    raw = base64.b32decode(padded.upper())
    assert raw[0] == 0x01  # CIDv1
    assert raw[1] == 0x71  # dag-cbor
    assert raw[2] == 0x12  # sha2-256
    assert raw[3] == 32  # digest length


def test_canonical_encode_rejects_nan_inf():
    import pytest

    with pytest.raises(ValueError):
        canonical_encode(float("nan"))
    with pytest.raises(ValueError):
        canonical_encode(float("inf"))


def test_cid_deterministic_across_processes():
    """No process-local state (no id(), no hash-seed dependence) feeds the CID."""
    script = (
        "import sys; sys.path.insert(0, %r); "
        "from provenance.cid import recipe_cid; "
        "print(recipe_cid('op', {'a': 1, 'b': [1, 2, 'x']}, ('parent1', 'parent2')))"
    ) % "src"
    outs = {
        subprocess.run(
            [sys.executable, "-c", script],
            cwd="packages/provenance",
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        for _ in range(2)
    }
    assert len(outs) == 1


def test_bytes_and_text_are_distinct():
    assert canonical_encode(b"x") != canonical_encode("x")


def test_cid_from_bytes_matches_recipe_cid_shape():
    assert cid_from_bytes(b"").startswith("b")
