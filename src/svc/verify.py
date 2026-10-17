"""Buyer-side verification — the 5 layers.

  L1 AUTHENTICITY  signature valid under the TRUSTED public key, and
                   issuer.public_key == trusted key (no rogue issuer)
  L2 INTEGRITY     sha256 of every subject file
  L3 EVIDENCE      sha256 + Merkle root + n_items of every evidence trace
  L4 SOUNDNESS     every claim value recomputed from evidence via its rule
                   (and, with rerun=True, re-executed from pinned artifacts)
  L5 CLAIMS        every claim status re-derived from value + threshold;
                   recommended_for == proven labels; not_recommended_for
                   superset of not-proven labels (overclaim => FAIL)

verify() -> report dict:
  {"ok": bool, "layers": [{layer, ok, detail, n, bad[]}, ...], "claims": [...]}
"""
import json
import os

from .canonical import merkle_root, sha256_file, load_jsonl
from .crypto import verify as crypto_verify
from .rules import recompute_field, status_from_threshold, derive_recommendations
from .schema import parse_rule, get_json_path
from .rerun import run_pinned, compare_metric


def _load_attested_doc(claim, base_dir):
    for f in claim["subject"].get("files", []):
        if f.get("role") == "attestation" and os.path.exists(os.path.join(base_dir, f["path"])):
            return json.load(open(os.path.join(base_dir, f["path"])))
    return None


def verify_claim(claim: dict, base_dir: str, trusted_pubkey: str,
                 rerun: bool = False, rerun_timeout_s: int = 3600) -> dict:
    report = {"ok": True, "layers": [], "claims": []}

    def add(layer, ok, detail, bad=None):
        report["layers"].append({"layer": layer, "ok": bool(ok),
                                 "detail": detail, "bad": bad or []})
        if not ok:
            report["ok"] = False

    # ---- L1 ----
    bad = []
    payload = {k: v for k, v in claim.items() if k != "signature"}
    if not crypto_verify(trusted_pubkey, payload, claim.get("signature", "")):
        bad.append("signature invalid")
    if claim.get("issuer", {}).get("public_key") != trusted_pubkey:
        bad.append("issuer key != trusted key")
    add("L1 authenticity", not bad, "valid" if not bad else "; ".join(bad), bad)

    # ---- L2 integrity: subject files ----
    bad = []
    for f in claim["subject"].get("files", []):
        p = os.path.join(base_dir, f["path"])
        if not os.path.exists(p):
            bad.append(f"{f['path']}:MISSING")
        elif sha256_file(p) != f["sha256"]:
            bad.append(f"{f['path']}:HASH")
    add("L2 integrity", not bad,
        f"{len(claim['subject'].get('files', []))} files match" if not bad
        else "; ".join(bad), bad)

    # ---- L3 evidence ----
    bad = []
    ev_cache = {}
    for e in claim["subject"].get("evidence", []):
        p = os.path.join(base_dir, e["path"])
        if not os.path.exists(p):
            bad.append(f"{e['path']}:MISSING")
            continue
        if sha256_file(p) != e["sha256"]:
            bad.append(f"{e['path']}:HASH")
            continue
        lines = load_jsonl(p)
        if len(lines) != e["n_items"]:
            bad.append(f"{e['path']}:COUNT {len(lines)}!={e['n_items']}")
            continue
        if merkle_root(lines) != e["merkle_root"]:
            bad.append(f"{e['path']}:MERKLE")
            continue
        ev_cache[e["path"]] = lines
    add("L3 evidence", not bad,
        f"{len(claim['subject'].get('evidence', []))} traces match" if not bad
        else "; ".join(bad), bad)

    attested_doc = _load_attested_doc(claim, base_dir)

    # ---- L4 soundness: recompute each claim value ----
    bad = []
    statuses = {}
    for c in claim["claims"]:
        rule = c["derivation"]["rule"]
        kind = parse_rule(rule)
        tol = float(c["derivation"].get("tolerance", 0.0))
        recomputed = None
        if kind[0] == "field":
            _, name, agg = kind
            evpath = c["derivation"]["evidence"]
            if evpath not in ev_cache:
                bad.append(f"{c['id']}: evidence unavailable ({evpath})")
                continue
            try:
                recomputed = recompute_field(ev_cache[evpath], name, agg)
            except (KeyError, ValueError) as ex:
                bad.append(f"{c['id']}: recompute error {ex}")
                continue
        elif kind[0] == "attested":
            if attested_doc is None:
                bad.append(f"{c['id']}: no pinned attestation document")
                continue
            try:
                recomputed = float(get_json_path(attested_doc, kind[1]))
            except (KeyError, IndexError, TypeError, ValueError) as ex:
                bad.append(f"{c['id']}: attested path error {ex}")
                continue
        elif kind[0] == "file":
            fpath = os.path.join(base_dir, kind[1])
            if not os.path.exists(fpath):
                bad.append(f"{c['id']}: file missing {kind[1]}")
                continue
            try:
                obj = json.load(open(fpath))
                recomputed = float(obj[kind[2]])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as ex:
                bad.append(f"{c['id']}: file field error {ex}")
                continue
        else:  # script
            spath = kind[1]
            sf = os.path.join(base_dir, spath)
            if not os.path.exists(sf):
                bad.append(f"{c['id']}: script missing {spath}")
                continue
            r = run_pinned(f"python3 {spath}", base_dir, timeout_s=rerun_timeout_s,
                           log_path=os.path.join(base_dir, f".svc_recompute_{c['id']}.log"))
            if not r["ok"]:
                bad.append(f"{c['id']}: recompute script failed: {r['error']}")
                continue
            try:
                recomputed = float(r["metrics"][kind[2]])
            except (KeyError, TypeError, ValueError) as ex:
                bad.append(f"{c['id']}: script output missing {kind[2]!r}: {ex}")
                continue
        if recomputed is not None:
            if abs(recomputed - float(c["value"])) > tol:
                bad.append(f"{c['id']}: value {c['value']} != recomputed {recomputed} (tol {tol})")
            else:
                statuses[c["id"]] = status_from_threshold(c["threshold"], float(c["value"]))
                report["claims"].append({"id": c["id"], "metric": c["metric"],
                                         "value": c["value"],
                                         "recomputed": recomputed,
                                         "status_claimed": c["status"],
                                         "status_derived": statuses[c["id"]]})
    add("L4 soundness", not bad,
        f"{len(report['claims'])}/{len(claim['claims'])} values recomputed" if not bad
        else "; ".join(bad), bad)

    # ---- L4b rerun (opt-in) ----
    if rerun:
        bad = []
        for c in claim["claims"]:
            rr = c["derivation"].get("rerun")
            if not rr:
                continue
            r = run_pinned(rr["command"], base_dir, timeout_s=rerun_timeout_s,
                           log_path=os.path.join(base_dir, f".svc_rerun_{c['id']}.log"))
            if not r["ok"]:
                bad.append(f"{c['id']}: rerun failed: {r['error']}")
                continue
            try:
                reproduced = float(r["metrics"][rr["metric_field"]])
            except (KeyError, TypeError, ValueError) as ex:
                bad.append(f"{c['id']}: rerun output missing {rr['metric_field']!r}")
                continue
            ok, detail = compare_metric(c["value"], reproduced,
                                        float(rr.get("tolerance", 0.0)))
            if not ok:
                bad.append(f"{c['id']}: {detail}")
            report["claims"].append({"id": c["id"], "rerun": reproduced, "detail": detail})
        add("L4b rerun", not bad,
            f"{sum(1 for c in claim['claims'] if c['derivation'].get('rerun'))} claims re-executed"
            if not bad else "; ".join(bad), bad)

    # ---- L5 claims: statuses + recommendation sets ----
    bad = []
    for c in claim["claims"]:
        if c["id"] in statuses and statuses[c["id"]] != c["status"]:
            bad.append(f"{c['id']}: status {c['status']} != derived {statuses[c['id']]}")
    rec = claim.get("recommendation")
    if rec is not None:
        derived = derive_recommendations(claim["claims"],
                                         {c["id"]: statuses.get(c["id"], c["status"])
                                          for c in claim["claims"]})
        if sorted(rec.get("recommended_for", [])) != derived["recommended_for"]:
            bad.append(f"recommended_for {rec.get('recommended_for')} != derived {derived['recommended_for']}")
        req = set(derived["required_not_recommended"])
        if not req <= set(rec.get("not_recommended_for", [])):
            bad.append(f"not_recommended_for missing {sorted(req - set(rec.get('not_recommended_for', [])))}")
    add("L5 claims", not bad, "statuses + recommendations re-derived" if not bad
        else "; ".join(bad), bad)

    return report


def format_report(report: dict, claim: dict) -> str:
    lines = [f"=== SVC VERIFY {claim.get('claim_id', '?')} ==="]
    for l in report["layers"]:
        lines.append(f"  [{'PASS' if l['ok'] else 'FAIL'}] {l['layer']}: {l['detail']}")
    for c in report["claims"]:
        if "recomputed" in c:
            flag = "OK" if c["status_claimed"] == c["status_derived"] else "MISMATCH"
            lines.append(f"  claim {c['id']}: value={c['value']} recomputed={c['recomputed']} "
                         f"status={c['status_claimed']} [{flag}]")
        if "rerun" in c:
            lines.append(f"  claim {c['id']}: rerun={c['rerun']} — {c['detail']}")
    lines.append("RESULT: " + ("PASS — all layers verified; claims re-derived"
                               if report["ok"] else "FAIL"))
    return "\n".join(lines)
