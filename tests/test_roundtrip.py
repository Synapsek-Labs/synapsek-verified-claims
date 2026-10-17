from conftest import seal
from svc.verify import verify_claim


def test_roundtrip_pass(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path)
    priv, pub = keys
    rep = verify_claim(sealed, ds, pub)
    assert rep["ok"], rep
    assert len(rep["layers"]) == 5
    for l in rep["layers"]:
        assert l["ok"], l


def test_verify_with_rerun_pass(keys, tmp_path):
    sealed, ds = seal(keys, tmp_path, with_rerun_script=True)
    priv, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=True)
    assert rep["ok"], rep
    assert any(l["layer"] == "L4b rerun" for l in rep["layers"])
