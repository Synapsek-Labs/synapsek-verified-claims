"""Claim construction and sealing (the ISSUER side).

`seal_claim` takes a claim skeleton (values optional) + a claim directory,
fills every hash/Merkle root/n_items from disk, derives claim statuses
from measured values + thresholds (the issuer cannot hand-pick 'proven'),
and signs the result. The private key is passed in-memory from a file the
issuer controls; only the public key ends up in the claim.
"""
import datetime
import os

from .canonical import merkle_root, sha256_file, load_jsonl, canonical_bytes, sha256_bytes
from .crypto import sign
from .rules import status_from_threshold
from .schema import SCHEMA_VERSION, validate_claim


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fill_evidence(claim: dict, base_dir: str):
    for e in claim["subject"].get("evidence", []):
        p = os.path.join(base_dir, e["path"])
        if not os.path.exists(p):
            raise FileNotFoundError(p)
        e["sha256"] = sha256_file(p)
        lines = load_jsonl(p)
        e["n_items"] = len(lines)
        e["merkle_root"] = merkle_root(lines)


def fill_files(claim: dict, base_dir: str):
    for f in claim["subject"].get("files", []):
        p = os.path.join(base_dir, f["path"])
        if not os.path.exists(p):
            raise FileNotFoundError(p)
        f["sha256"] = sha256_file(p)


def seal_claim(claim: dict, base_dir: str, privkey_b64: str,
               issuer_id: str = None, measured: dict = None) -> dict:
    """Fill hashes + statuses + signature -> sealed claim (dict).

    measured: {claim_id: value} — authoritative measured values (e.g. from
    the pinned rerun). Claims without an entry must already carry `value`.
    Status is ALWAYS re-derived from value+threshold here; a skeleton that
    contradicts its own numbers fails validation after sealing.
    """
    measured = measured or {}
    fill_files(claim, base_dir)
    fill_evidence(claim, base_dir)
    for c in claim["claims"]:
        if c["id"] in measured:
            c["value"] = measured[c["id"]]
        c["status"] = status_from_threshold(c["threshold"], c["value"])
    # config hash (canonical) so config edits invalidate the signature
    cfg = dict(claim.get("pinned", {}).get("config", {}))
    cfg.pop("sha256", None)
    claim.setdefault("pinned", {}).setdefault("config", cfg)
    claim["pinned"]["config"]["sha256"] = sha256_bytes(canonical_bytes(cfg))
    claim["svc_version"] = SCHEMA_VERSION
    claim["created_at"] = claim.get("created_at") or now_utc()
    claim.setdefault("issuer", {})
    pub = claim["issuer"].get("public_key")
    if not pub:
        raise ValueError("issuer.public_key required in skeleton")
    payload = {k: v for k, v in claim.items() if k != "signature"}
    claim["signature"] = sign(privkey_b64, payload)
    problems = validate_claim(claim)
    if problems:
        raise ValueError("sealed claim failed validation: " + "; ".join(problems))
    return claim
