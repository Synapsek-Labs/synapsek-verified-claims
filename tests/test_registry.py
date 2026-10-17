import json

from conftest import seal
from svc import registry
from svc.canonical import sha256_bytes, canonical_bytes


def test_add_lookup_list(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    reg = str(tmp_path / "registry.json")
    entry = registry.add(reg, sealed, "synapsek.test/0")
    assert entry["claim_id"] == "synapsek.claim/test/1"
    assert registry.lookup(reg, "synapsek.claim/test/1") is not None
    assert registry.lookup(reg, "nope") is None
    reg2 = registry.load(reg)
    assert len(reg2["entries"]) == 1


def test_duplicate_add_rejected(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    reg = str(tmp_path / "registry.json")
    registry.add(reg, sealed, "synapsek.test/0")
    try:
        registry.add(reg, sealed, "synapsek.test/0")
        assert False, "expected duplicate rejection"
    except ValueError:
        pass


def test_registry_hash_catches_claim_edit(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    reg = str(tmp_path / "registry.json")
    entry = registry.add(reg, sealed, "synapsek.test/0")
    tampered = json.loads(json.dumps(sealed))
    tampered["claims"][0]["value"] = 0.1
    payload = {k: v for k, v in tampered.items() if k != "signature"}
    assert entry["claim_sha256"] != sha256_bytes(canonical_bytes(payload))
