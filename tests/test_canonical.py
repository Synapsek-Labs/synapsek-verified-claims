from svc.canonical import canonical_bytes, merkle_root, sha256_file
import hashlib


def test_canonical_stable_under_key_order():
    a = {"b": 1, "a": {"d": 2, "c": [1, 2, 3]}}
    b = {"a": {"c": [1, 2, 3], "d": 2}, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_tamper_changes_bytes():
    a = {"x": 1}
    assert canonical_bytes(a) != canonical_bytes({"x": 2})
    assert canonical_bytes(a) != canonical_bytes({"x": 1, "y": 0})


def test_merkle_deterministic_and_order_sensitive():
    items = [{"i": 1}, {"i": 2}, {"i": 3}]
    r1 = merkle_root(items)
    r2 = merkle_root([{"i": 1}, {"i": 2}, {"i": 3}])
    assert r1 == r2
    assert merkle_root(list(reversed(items))) != r1
    assert len(r1) == 64


def test_merkle_empty():
    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello")
    assert sha256_file(str(p)) == hashlib.sha256(b"hello").hexdigest()
