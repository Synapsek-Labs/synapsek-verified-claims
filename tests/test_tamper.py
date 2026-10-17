import json

from conftest import seal, make_claim_dir, build_skeleton
from svc.claim import seal_claim
from svc.verify import verify_claim


def _seal_and_tamper_file(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    with open(ds + "/artifact.bin", "ab") as f:
        f.write(b"tampered")
    return sealed, ds


def test_tampered_artifact_fails_L2(keys, tmp_path):
    sealed, ds = _seal_and_tamper_file(keys, tmp_path)
    _, pub = keys
    rep = verify_claim(sealed, ds, pub)
    assert not rep["ok"]
    l2 = next(l for l in rep["layers"] if l["layer"] == "L2 integrity")
    assert not l2["ok"]
    assert any("HASH" in b for b in l2["bad"])


def test_tampered_evidence_fails_L3(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    p = ds + "/evidence/run1.jsonl"
    with open(p, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    lines[1] = json.dumps({"x": 2.0, "y": 0.99})
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    _, pub = keys
    rep = verify_claim(sealed, ds, pub)
    assert not rep["ok"]
    l3 = next(l for l in rep["layers"] if l["layer"] == "L3 evidence")
    assert not l3["ok"]


def test_value_edit_after_signing_fails_L1(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    sealed["claims"][0]["value"] = 99.0
    _, pub = keys
    rep = verify_claim(sealed, ds, pub)
    assert not rep["ok"]
    l1 = next(l for l in rep["layers"] if l["layer"] == "L1 authenticity")
    assert not l1["ok"]


def test_rerun_drift_fails_L4b(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path, with_rerun_script=True)
    # drift the DATA (not in manifest-verified evidence path? data.jsonl IS
    # manifest-verified) -> L2 + L4b both fail; assert L4b specifically
    with open(ds + "/data.jsonl", "a") as f:
        f.write(json.dumps({"x": 99.0, "y": 0.1}) + "\n")
    _, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=True)
    assert not rep["ok"]
    l4b = next((l for l in rep["layers"] if l["layer"] == "L4b rerun"), None)
    assert l4b is not None and not l4b["ok"]


def test_overclaimed_recommendation_fails_L5(keys, tmp_path):
    # value below threshold => status derived 'not_proven', but the
    # recommendation still lists the label as recommended_for
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path, evidence=[
        {"x": 1.0, "y": 0.4}, {"x": 2.0, "y": 0.41}, {"x": 3.0, "y": 0.42}])
    skel = build_skeleton(d, pub)
    skel["claims"][0]["value"] = 0.41  # < 0.5 threshold
    sealed = seal_claim(skel, ds, priv)
    assert sealed["claims"][0]["status"] == "not_proven"
    rep = verify_claim(sealed, ds, pub)
    assert not rep["ok"]
    l5 = next(l for l in rep["layers"] if l["layer"] == "L5 claims")
    assert not l5["ok"]
    assert any("recommended_for" in b for b in l5["bad"])


def test_rogue_issuer_key_fails_L1(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    from svc.crypto import gen_keypair
    _, other_pub = gen_keypair()
    rep = verify_claim(sealed, ds, other_pub)
    assert not rep["ok"]
