"""svc — command line for Synapsek Verified Claims.

  svc attest  SKELETON.json --key PRIV --base-dir DIR [--measured KEY=VAL ...] [--out F]
  svc verify  CLAIM.json     --trusted-pubkey PUB --base-dir DIR [--rerun] [--registry REG] [--json]
  svc registry add|list|lookup
  svc keygen  --out-dir DIR

Exit codes: 0 = PASS/ok, 1 = FAIL/error.
"""
import argparse
import json
import os
import sys


def _read_json(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def cmd_attest(a):
    from .claim import seal_claim
    from .crypto import read_key_file
    claim = _read_json(a.skeleton)
    measured = {}
    for m in (a.measured or []):
        k, v = m.split("=", 1)
        measured[k] = float(v)
    sealed = seal_claim(claim, a.base_dir, read_key_file(a.key),
                        issuer_id=claim.get("issuer", {}).get("id", "unknown"))
    out = a.out or os.path.join(a.base_dir, "claim.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sealed, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"sealed {sealed['claim_id']} -> {out}")
    print(f"  files {len(sealed['subject'].get('files', []))}, "
          f"evidence {len(sealed['subject'].get('evidence', []))}, "
          f"claims {len(sealed['claims'])}")
    for c in sealed["claims"]:
        print(f"  {c['id']}: {c['value']} {c.get('unit','')} -> {c['status']}")


def cmd_verify(a):
    from .verify import verify_claim, format_report
    from .crypto import read_key_file
    claim = _read_json(a.claim)
    pub = read_key_file(a.trusted_pubkey)
    if a.registry:
        from . import registry
        from .canonical import sha256_bytes, canonical_bytes
        entry = registry.lookup(a.registry, claim["claim_id"])
        if entry is None:
            print(f"FAIL: claim {claim['claim_id']} not in registry {a.registry}")
            sys.exit(1)
        if entry["issuer_public_key"] != pub:
            print("FAIL: registry key != trusted key")
            sys.exit(1)
        payload = {k: v for k, v in claim.items() if k != "signature"}
        if entry["claim_sha256"] != sha256_bytes(canonical_bytes(payload)):
            print("FAIL: claim document != registry hash")
            sys.exit(1)
        print(f"registry: {claim['claim_id']} matches entry "
              f"(issuer {entry['issuer_id']})")
    report = verify_claim(claim, a.base_dir, pub, rerun=a.rerun,
                          rerun_timeout_s=a.rerun_timeout)
    if a.json:
        print(json.dumps({"claim": claim["claim_id"], **report}, indent=1))
    else:
        print(format_report(report, claim))
    sys.exit(0 if report["ok"] else 1)


def cmd_registry(a):
    from . import registry
    if a.registry_cmd == "list":
        reg = registry.load(a.registry)
        for e in reg["entries"]:
            print(f"{e['claim_id']}  issuer={e['issuer_id']}  "
                  f"key={e['issuer_public_key'][:12]}...  created={e['created_at']}")
    elif a.registry_cmd == "add":
        entry = registry.add(a.registry, _read_json(a.claim), a.issuer_id)
        print(f"added {entry['claim_id']}")
    elif a.registry_cmd == "lookup":
        e = registry.lookup(a.registry, a.claim_id)
        print(json.dumps(e, indent=1) if e else "not found")
        sys.exit(0 if e else 1)


def cmd_keygen(a):
    from .crypto import gen_keypair
    os.makedirs(a.out_dir, exist_ok=True)
    priv, pub = gen_keypair()
    kp = os.path.join(a.out_dir, "issuer_ed25519")
    pp = os.path.join(a.out_dir, "issuer_ed25519.pub")
    with open(kp, "w", encoding="utf-8") as f:
        f.write(priv + "\n")
    os.chmod(kp, 0o600)
    with open(pp, "w", encoding="utf-8") as f:
        f.write(pub + "\n")
    print(f"keypair written: {kp} (mode 600) / {pp}")


def main():
    ap = argparse.ArgumentParser(prog="svc")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("attest", help="seal + sign a claim skeleton")
    pa.add_argument("skeleton")
    pa.add_argument("--key", required=True)
    pa.add_argument("--base-dir", required=True)
    pa.add_argument("--measured", action="append", help="claim_id=value")
    pa.add_argument("--out")
    pa.set_defaults(fn=cmd_attest)

    pv = sub.add_parser("verify", help="buyer-side verification")
    pv.add_argument("claim")
    pv.add_argument("--trusted-pubkey", required=True)
    pv.add_argument("--base-dir", required=True)
    pv.add_argument("--rerun", action="store_true",
                    help="also re-execute pinned eval commands")
    pv.add_argument("--rerun-timeout", type=int, default=3600)
    pv.add_argument("--registry")
    pv.add_argument("--json", action="store_true")
    pv.set_defaults(fn=cmd_verify)

    pr = sub.add_parser("registry")
    pr.add_argument("registry_cmd", choices=["add", "list", "lookup"])
    pr.add_argument("registry", nargs="?", help="registry.json path")
    pr.add_argument("--claim", help="claim file (for add)")
    pr.add_argument("--issuer-id", default="unknown")
    pr.add_argument("claim_id", nargs="?", help="for lookup")
    pr.set_defaults(fn=cmd_registry)

    pk = sub.add_parser("keygen")
    pk.add_argument("--out-dir", required=True)
    pk.set_defaults(fn=cmd_keygen)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
