"""Claim registry — the trust anchor a buyer consults.

A registry is a plain JSON file: who issued which claim, under which
public key, and the sha256 of the claim document. Buyers verify the claim
hash against the registry entry, then verify the claim under that entry's
public key (which they trust out-of-band).

This mirrors the v11 registry (attest/v11/registry.json) and is portable:
the same file shape works for a public registry endpoint later.
"""
import json
import os

from .canonical import sha256_bytes, canonical_bytes
from .schema import SCHEMA_VERSION


def _path(reg, *parts):
    return os.path.join(reg, *parts) if isinstance(reg, (str, os.PathLike)) else None


def load(registry_path: str) -> dict:
    if not os.path.exists(registry_path):
        return {"svc_version": SCHEMA_VERSION, "entries": []}
    return json.load(open(registry_path))


def save(registry_path: str, reg: dict):
    os.makedirs(os.path.dirname(os.path.abspath(registry_path)), exist_ok=True)
    tmp = registry_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, registry_path)


def add(registry_path: str, claim: dict, issuer_id: str) -> dict:
    reg = load(registry_path)
    payload = {k: v for k, v in claim.items() if k != "signature"}
    entry = {
        "claim_id": claim["claim_id"],
        "issuer_id": issuer_id,
        "issuer_public_key": claim["issuer"]["public_key"],
        "claim_sha256": sha256_bytes(canonical_bytes(payload)),
        "claim_full_sha256": sha256_bytes(canonical_bytes(claim)),
        "created_at": claim.get("created_at", ""),
        "subject_id": claim["subject"].get("id", ""),
        "claims_n": len(claim.get("claims", [])),
    }
    for e in reg["entries"]:
        if e["claim_id"] == entry["claim_id"]:
            raise ValueError(f"duplicate claim_id {entry['claim_id']}")
    reg["entries"].append(entry)
    save(registry_path, reg)
    return entry


def lookup(registry_path: str, claim_id: str):
    reg = load(registry_path)
    for e in reg["entries"]:
        if e["claim_id"] == claim_id:
            return e
    return None
