"""Regression tests for the 2026-10-17 independent audit findings.

1 (critical): script execution must require explicit --rerun consent AND
              L1+L2+L3 all passed; no shell semantics in pinned commands.
2 (high):     claim status must be derived from the RECOMPUTED value, never
              the claimed value; non-finite values/tolerances always FAIL.
3 (high):     every derivation input must be a manifest-pinned, hash-verified
              path inside the claim directory.
5 (high):     evidence handling must be explicit-UTF-8 (Windows-safe).
"""
import json
import math
import os

import svc.verify as V
from conftest import make_claim_dir, build_skeleton, seal, DATA_LINES
from svc.claim import seal_claim
from svc.verify import verify_claim, _safe_resolve


def _seal_script_claim(keys, tmp_path, pop_rerun_entry=True):
    """Seal a claim whose derivation rule is script:code/eval.py#mean_y
    (code/eval.py is manifest-pinned)."""
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path, with_rerun_script=True)
    skel = build_skeleton(d, pub, with_rerun=True)
    skel["claims"][0]["derivation"]["rule"] = "script:code/eval.py#mean_y"
    if pop_rerun_entry:
        skel["claims"][0]["derivation"].pop("rerun", None)
    return seal_claim(skel, ds, priv), ds


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, *a, **k):
        self.calls.append((a, k))
        return {"ok": True, "metrics": {"mean_y": 0.55}, "error": None,
                "duration_s": 0}


# ---- Finding 1: execution consent + layer gates -------------------------

def test_script_rule_not_executed_without_rerun(keys, tmp_path, monkeypatch):
    spy = _Spy()
    monkeypatch.setattr(V, "run_pinned", spy)
    sealed, ds = _seal_script_claim(keys, tmp_path)
    _, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=False)
    assert spy.calls == [], "executor invoked without --rerun consent"
    l4 = next(l for l in rep["layers"] if l["layer"] == "L4 soundness")
    assert not l4["ok"]
    assert not rep["ok"]


def test_script_rule_not_executed_after_L1_failure(keys, tmp_path, monkeypatch):
    spy = _Spy()
    monkeypatch.setattr(V, "run_pinned", spy)
    sealed, ds = _seal_script_claim(keys, tmp_path)
    sealed["claims"][0]["value"] = 99.0  # break the signature
    _, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=True)
    assert spy.calls == [], "executor invoked after L1 failure"
    assert not rep["ok"]


def test_script_rule_not_executed_after_L2_failure(keys, tmp_path, monkeypatch):
    spy = _Spy()
    monkeypatch.setattr(V, "run_pinned", spy)
    sealed, ds = _seal_script_claim(keys, tmp_path)
    with open(ds + "/artifact.bin", "ab") as f:
        f.write(b"tampered")
    _, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=True)
    assert spy.calls == [], "executor invoked after L2 failure"
    assert not rep["ok"]


def test_rerun_block_not_executed_after_L1_failure(keys, tmp_path, monkeypatch):
    spy = _Spy()
    monkeypatch.setattr(V, "run_pinned", spy)
    sealed, ds = seal(keys, tmp_path, with_rerun_script=True)
    sealed["claims"][0]["value"] = 99.0  # break the signature
    _, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=True)
    assert spy.calls == [], "rerun executed after L1 failure"
    l4b = next(l for l in rep["layers"] if l["layer"] == "L4b rerun")
    assert not l4b["ok"] and "NOT executed" in l4b["detail"]


def test_script_rule_executes_with_consent_and_intact_bundle(keys, tmp_path):
    """The happy path still works: consent + full L1/L2/L3 => execution."""
    sealed, ds = _seal_script_claim(keys, tmp_path)
    _, pub = keys
    rep = verify_claim(sealed, ds, pub, rerun=True)
    assert rep["ok"], rep
    assert any(l["layer"] == "L4 soundness" and l["ok"] for l in rep["layers"])


def test_rerun_command_has_no_shell_semantics(keys, tmp_path):
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path, with_rerun_script=True)
    skel = build_skeleton(d, pub, with_rerun=True)
    skel["claims"][0]["derivation"]["rerun"]["command"] = \
        "python3 -c 'import sys; assert len(sys.argv) == 1' && touch PWNED"
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub, rerun=True)
    pwned = ds + "/PWNED"
    assert not os.path.exists(pwned), "shell metacharacter was executed"
    l4b = next(l for l in rep["layers"] if l["layer"] == "L4b rerun")
    assert not l4b["ok"]


# ---- Finding 2: status from recomputed value; finite guards --------------

def test_status_derived_from_recomputed_not_claimed(keys, tmp_path):
    """Auditor scenario: evidence mean 0.55, threshold min 0.56, claimed
    0.57 within tolerance 0.03 -> L4 matches, L5 must FAIL (overclaim)."""
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path)  # y = [0.5, 0.6, 0.55] -> mean 0.55
    skel = build_skeleton(d, pub)
    skel["claims"][0]["value"] = 0.57
    skel["claims"][0]["derivation"]["tolerance"] = 0.03
    skel["claims"][0]["threshold"] = {"min": 0.56}
    skel["claims"][0]["status"] = "proven"
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub)
    l4 = next(l for l in rep["layers"] if l["layer"] == "L4 soundness")
    l5 = next(l for l in rep["layers"] if l["layer"] == "L5 claims")
    assert l4["ok"], l4
    assert not l5["ok"], "overclaim must fail L5"
    derived = next(c for c in rep["claims"] if c["id"] == "mean_y")
    assert derived["status_derived"] == "not_proven"
    assert not rep["ok"]


def test_nan_tolerance_rejected(keys, tmp_path):
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path)
    skel = build_skeleton(d, pub)
    skel["claims"][0]["value"] = 999.0
    skel["claims"][0]["derivation"]["tolerance"] = float("nan")
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub)
    l4 = next(l for l in rep["layers"] if l["layer"] == "L4 soundness")
    assert not l4["ok"]
    assert any("non-finite tolerance" in b for b in l4["bad"])
    assert not rep["ok"]


def test_non_finite_claimed_value_rejected(keys, tmp_path):
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path)
    skel = build_skeleton(d, pub)
    skel["claims"][0]["value"] = float("nan")
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub)
    l4 = next(l for l in rep["layers"] if l["layer"] == "L4 soundness")
    assert not l4["ok"]
    assert any("non-finite claimed value" in b for b in l4["bad"])


# ---- Finding 3: derivation inputs must be manifest-pinned -----------------

def test_file_rule_unmanifested_path_rejected(keys, tmp_path):
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path)
    unlisted = {"v": 0.99}
    with open(ds + "/unlisted.json", "w", encoding="utf-8") as f:
        json.dump(unlisted, f)
    skel = build_skeleton(d, pub)
    skel["claims"][0]["derivation"]["rule"] = "file:unlisted.json#v"
    skel["claims"][0]["value"] = 0.99
    skel["claims"][0]["threshold"] = {"min": 0.5}
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub)
    l4 = next(l for l in rep["layers"] if l["layer"] == "L4 soundness")
    assert not l4["ok"]
    assert any("not in verified manifest" in b for b in l4["bad"])
    assert not rep["ok"]


def test_file_rule_path_escape_rejected(keys, tmp_path):
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path)
    with open(str(tmp_path) + "/outside.json", "w", encoding="utf-8") as f:
        json.dump({"v": 0.99}, f)
    skel = build_skeleton(d, pub)
    skel["claims"][0]["derivation"]["rule"] = "file:../outside.json#v"
    skel["claims"][0]["value"] = 0.99
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub)
    l4 = next(l for l in rep["layers"] if l["layer"] == "L4 soundness")
    assert not l4["ok"]
    assert not rep["ok"]


def test_safe_resolve_rejects_escapes(tmp_path):
    ds = str(tmp_path / "claimdir")
    os.makedirs(ds)
    assert _safe_resolve(ds, "../x.json") is None
    assert _safe_resolve(ds, "/etc/passwd") is None
    assert _safe_resolve(ds, "a/../../x.json") is None
    assert _safe_resolve(ds, "~/.ssh/id") is None
    assert _safe_resolve(ds, "") is None
    inside = _safe_resolve(ds, "code/eval.py")
    assert inside is not None and inside.startswith(os.path.realpath(ds))


# ---- Finding 5: explicit UTF-8 --------------------------------------------

def test_utf8_evidence_roundtrip(keys, tmp_path):
    ev = [dict(r, text="café naïve — 日本語") for r in DATA_LINES]
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path, evidence=ev)
    skel = build_skeleton(d, pub)
    skel["claims"][0]["value"] = sum(r["y"] for r in ev) / 3
    sealed = seal_claim(skel, ds, priv)
    rep = verify_claim(sealed, ds, pub)
    assert rep["ok"], rep
