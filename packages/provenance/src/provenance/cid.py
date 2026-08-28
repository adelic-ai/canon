"""Real, self-describing CIDs for recipe nodes — `contracts/cid.md` PIN 2.

Implements the pinned scheme with zero dependencies (matching this package's
"zero heavy deps" policy, `pyproject.toml`): a minimal canonical-CBOR encoder
(DAG-CBOR's canonical rules — sorted map keys, shortest-form integers, no
indefinite-length items, no NaN/Inf) plus real CIDv1 bytes (multicodec +
multihash + multibase), so the id a recipe node gets is an actual, decodable,
self-describing CID — not an ad hoc hex string.

This is deliberately **not** a general CBOR library. It only needs to encode
the shapes an ``Activity``'s recipe produces: ``str``, ``bytes``, ``int``,
``float``, ``bool``, ``None``, ``list``/``tuple``, and ``dict`` (string keys).

Scope (PIN 4 / custody.md — do not extend this to evidence sources): an
evidence source's id is its raw sha2-256 hex digest (``evidence_digest``), by
design — it must equal a plain in-toto product digest, not a wrapped CID. This
module's :func:`recipe_cid` is only for **derived** (Activity) nodes and
**by-reference** sources.
"""
from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from typing import Any

# ── canonical CBOR (DAG-CBOR canonical form) ────────────────────────────────

_MT_UINT = 0
_MT_NEGINT = 1
_MT_BYTES = 2
_MT_TEXT = 3
_MT_ARRAY = 4
_MT_MAP = 5
_MT_SIMPLE_FLOAT = 7


def _encode_head(major: int, value: int) -> bytes:
    """The CBOR initial-byte(s) for one major type + argument, shortest form."""
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 2**8:
        return bytes([(major << 5) | 24, value])
    if value < 2**16:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError(f"value {value} exceeds CBOR's 64-bit argument width")


def canonical_encode(value: Any) -> bytes:
    """Deterministic canonical-CBOR bytes for ``value``.

    ``int`` and ``float`` are distinct encodings (PIN 3: ``1`` and ``1.0`` must not
    collide) — bool is checked before int (``bool`` is an ``int`` subclass in Python).
    Dict keys must be ``str`` and are sorted by their encoded bytes (DAG-CBOR's
    canonical map-key order), giving one canonical byte string per logical value
    regardless of Python dict insertion order.
    """
    if value is None:
        return bytes([(_MT_SIMPLE_FLOAT << 5) | 22])  # simple(22) = null
    if isinstance(value, bool):
        return bytes([(_MT_SIMPLE_FLOAT << 5) | (21 if value else 20)])  # simple(20/21)
    if isinstance(value, int):
        if value >= 0:
            return _encode_head(_MT_UINT, value)
        return _encode_head(_MT_NEGINT, -value - 1)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/Inf are prohibited in a canon recipe (contracts/cid.md PIN 2)")
        import struct

        return bytes([(_MT_SIMPLE_FLOAT << 5) | 27]) + struct.pack(">d", value)
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _encode_head(_MT_TEXT, len(b)) + b
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        return _encode_head(_MT_BYTES, len(b)) + b
    if isinstance(value, Mapping):
        items = [(canonical_encode(k), v) for k, v in value.items()]
        if any(not isinstance(k, str) for k in value):
            raise TypeError("canonical_encode only supports string-keyed maps")
        items.sort(key=lambda kv: kv[0])
        out = _encode_head(_MT_MAP, len(items))
        for k_bytes, v in items:
            out += k_bytes + canonical_encode(v)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        out = _encode_head(_MT_ARRAY, len(value))
        for item in value:
            out += canonical_encode(item)
        return out
    raise TypeError(f"canonical_encode: unsupported type {type(value).__name__}")


# ── CIDv1 (multicodec + multihash + multibase) ──────────────────────────────

_CIDV1 = 0x01
_CODEC_DAG_CBOR = 0x71
_MULTIHASH_SHA2_256 = 0x12
_DIGEST_LEN = 32

_B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"  # RFC 4648 base32, lowercase, no padding


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _base32_nopad(data: bytes) -> str:
    bits = "".join(f"{byte:08b}" for byte in data)
    chars = []
    for i in range(0, len(bits), 5):
        chunk = bits[i : i + 5]
        chunk = chunk.ljust(5, "0")
        chars.append(_B32_ALPHABET[int(chunk, 2)])
    return "".join(chars)


def cid_from_bytes(payload: bytes, *, codec: int = _CODEC_DAG_CBOR) -> str:
    """Wrap ``sha256(payload)`` as a self-describing CIDv1 string: multibase 'b'
    (base32) + CIDv1 varint + codec varint + multihash (sha2-256 code + length + digest)."""
    digest = hashlib.sha256(payload).digest()
    multihash = _varint(_MULTIHASH_SHA2_256) + _varint(_DIGEST_LEN) + digest
    cid_bytes = _varint(_CIDV1) + _varint(codec) + multihash
    return "b" + _base32_nopad(cid_bytes)


def recipe_cid(op_name: str, params: Any, parent_cids: "Sequence[str]") -> str:
    """The CID for a recipe node: ``{op_name, params, parents}`` canonically encoded,
    then wrapped as a real dag-cbor/sha2-256 CIDv1 (`contracts/cid.md` PIN 1 + PIN 2)."""
    recipe = {"op_name": op_name, "params": dict(params), "parents": list(parent_cids)}
    return cid_from_bytes(canonical_encode(recipe))
