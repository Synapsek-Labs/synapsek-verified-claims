import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from svc.crypto import gen_keypair
from svc.claim import seal_claim
from svc.verify import verify_claim


DATA_LINES = [
    {"x": 1.0, "y": 0.5},
    {"x": 2.0, "y": 0.6},
    {"x": 3.0, "y": 0.55},
]


@pytest.fixture()
def keys():
    priv, pub = gen_keypair()
    return priv, pub


def make_claim_dir(tmp_path, evidence=DATA_LINES, extra_files=True,
                   with_rerun_script=False):
    d = tmp_path / "claimdir"
    d.mkdir()
    (d / "evidence").mkdir()
    (d / "code").mkdir()
    # artifact (fake model weights)
    (d / "artifact.bin").write_bytes(b"\x00" * 64 + b"artifact")
    # data
    (d / "data.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in evidence))
    # evidence trace (per-item rows, what the metric recomputes from)
    ev = d / "evidence" / "run1.jsonl"
    ev.write_text("".join(json.dumps(x) + "\n" for x in evidence))
    # rerun script: reads data.jsonl, prints mean(y)
    if with_rerun_script:
        import base64 as _b64
        (d / "code" / "eval.py").write_text(_b64.b64decode("aW1wb3J0IGpzb24Kcm93cyA9IFtqc29uLmxvYWRzKGwpIGZvciBsIGluIG9wZW4oJ2RhdGEuanNvbmwnKSBpZiBsLnN0cmlwKCldCnByaW50KGpzb24uZHVtcHMoeydtZWFuX3knOiBzdW0oclsneSddIGZvciByIGluIHJvd3MpIC8gbGVuKHJvd3MpfSkpCg==").decode())
    return d, str(d)


def build_skeleton(d, pub, with_rerun=False):
    files = [
        {"path": "artifact.bin", "role": "artifact"},
        {"path": "data.jsonl", "role": "data"},
        {"path": "code/eval.py", "role": "code"},
    ] if with_rerun else [
        {"path": "artifact.bin", "role": "artifact"},
        {"path": "data.jsonl", "role": "data"},
    ]
    return {
        "claim_id": "synapsek.claim/test/1",
        "subject": {
            "kind": "pipeline",
            "id": "test-pipeline",
            "description": "synthetic test pipeline",
            "base_dir": ".",
            "files": files,
            "evidence": [{"path": "evidence/run1.jsonl"}],
        },
        "pinned": {
            "environment": {"python": "3.14", "device": "cpu"},
            "dataset": {"id": "test-data", "n": 3},
            "config": {"metric": "mean_y"},
        },
        "claims": [{
            "id": "mean_y",
            "metric": "mean_y",
            "value": sum(r["y"] for r in DATA_LINES) / 3,
            "unit": "score",
            "threshold": {"min": 0.5},
            "status": "proven",
            "label": "quality_score",
            "derivation": {
                "evidence": "evidence/run1.jsonl",
                "rule": "field:y|mean",
                **({"rerun": {"command": "python3 code/eval.py",
                              "metric_field": "mean_y", "tolerance": 1e-9}}
                   if with_rerun else {}),
            },
        }],
        "recommendation": {
            "recommended_for": ["quality_score"],
            "not_recommended_for": ["everything_else"],
        },
        "disclosures": ["synthetic test claim"],
        "issuer": {"id": "synapsek.test/0", "public_key": pub},
    }


def seal(keys, tmp_path, **kw):
    priv, pub = keys
    d, ds = make_claim_dir(tmp_path, **{k: v for k, v in kw.items()
                                        if k in ("evidence", "extra_files", "with_rerun_script")})
    skel = build_skeleton(d, pub, with_rerun=kw.get("with_rerun_script", False))
    sealed = seal_claim(skel, ds, priv)
    return sealed, ds
