"""Deterministic serialization + hashing primitives (the signed payload).

Ported from the Synapsek v1.1 attestation engine (attest_lib.py), which has
been buyer-verified (G4 clean room). Same algorithms, same byte format —
an SVC claim and a v1.1 attestation share canonical bytes for the same
JSON object, so the two ecosystems interoperate.
"""
import hashlib
import json


def canonical_bytes(obj) -> bytes:
    """Deterministic JSON: sorted keys, compact separators, utf-8.

    This exact byte string is what gets signed — any semantic or
    byte-level tamper breaks the signature.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def merkle_root(items) -> str:
    """SHA-256 Merkle root over a list of JSON-serializable items.

    leaf = sha256(canonical(item)); odd nodes duplicated.
    Empty list -> sha256(b""). Order-sensitive: evidence order is part of
    the claim.
    """
    if not items:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(canonical_bytes(it)).digest() for it in items]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def load_jsonl(path: str) -> list:
    """Per-item trace JSONL -> list of dicts (order-preserving)."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
