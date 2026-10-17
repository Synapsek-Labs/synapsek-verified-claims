"""Ed25519 signing/verification for SVC claims.

Key custody model (unchanged from the v1.1 attestation system):
  - The issuer (compiler/verifier) holds the private key; ONLY the
    public key (base64url, no padding) is embedded in claims and shipped
    with the registry.
  - Buyers verify against the TRUSTED public key they hold out-of-band
    (registry lookup, key ceremony). issuer.public_key must equal the
    trusted key — a rogue issuer cannot self-attest under a different key.

Key files are 44-byte raw Ed25519 seeds (private) / 32-byte raw public
keys, base64url-encoded without padding.
"""
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PublicFormat, PrivateFormat)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def gen_keypair():
    """-> (priv_b64, pub_b64). For new attestation authorities."""
    key = Ed25519PrivateKey.generate()
    pub = _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    priv = _b64(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    return priv, pub


def read_key_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def sign(privkey_b64: str, payload: dict) -> str:
    from .canonical import canonical_bytes
    key = Ed25519PrivateKey.from_private_bytes(_unb64(privkey_b64))
    return _b64(key.sign(canonical_bytes(payload)))


def verify(pubkey_b64: str, payload: dict, signature_b64: str) -> bool:
    """Return True iff signature_b64 is a valid signature of
    canonical_bytes(payload) under pubkey_b64. Never raises."""
    from .canonical import canonical_bytes
    try:
        key = Ed25519PublicKey.from_public_bytes(_unb64(pubkey_b64))
        key.verify(_unb64(signature_b64), canonical_bytes(payload))
        return True
    except Exception:
        return False
