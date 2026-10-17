# Release checklist — synapsek-claims v0.1.0

Prepared 2026-10-17. All build/verify steps below were already executed on
Cherry; the remaining ~10 minutes are YOUR calls (org, account, publish).

## Already done (on Cherry, /root/synapsek-verified-claims)

- [x] package builds: `pip install -e .` clean, `python3 -m compileall` clean
- [x] 16/16 tests pass (roundtrip, tamper L1/L2/L3/L4b/L5, registry, canonical)
- [x] example 1 sealed + verified PASS (incl. bit-exact CPU rerun) + tamper-tested
- [x] example 2 sealed + verified PASS (13 claims: 4 not_proven + 9 proven) + tamper-tested
- [x] both claims registered in registry/registry.json under issuer
      synapsek.compiler/v1 (public key MHYuRK-KEKtx3w-MQYnEJ7oiHWWJsJfP0WzNwn_Fi1M)
- [x] leak scan: no private key material anywhere in the tree (public key only)

## Your steps (~10 min)

1. **Review** (2 min): open `examples/*/claim.json` and the two
   `svc verify ... --rerun` outputs above. The claim text is the public face
   of the project — read the disclosures.
2. **GitHub** (3 min): push to the created repo
   `Synapsek-Labs/synapsek-verified-claims` (public). From the tree:
   ```
   cd /root/synapsek-verified-claims
   git init -b main && git add -A && git commit -m "synapsek-claims v0.1.0"
   git remote add origin git@github.com:Synapsek-Labs/synapsek-verified-claims.git
   git push -u origin main
   git tag v0.1.0 && git push origin v0.1.0
   ```
   (`.gitignore` already excludes the 160MB `encoder.pt`, Python cache,
   `.svc_*` rerun logs.)
3. **Release asset** (2 min): GitHub → repo → Releases → `v0.1.0` → attach
   `examples/pipeline-dedup/artifact/encoder.pt` (160MB). Fresh clones get a
   README pointer; verify of example 1 needs that asset placed back into
   `artifact/encoder.pt`.
4. **PyPI** (3 min): create the account/owner (suggested: user `synapsek` or
   `synapsek-claims`; project is `synapsek-claims`, already named in
   pyproject). Then:
   ```
   pip install build twine
   python -m build            # -> dist/synapsek_claims-0.1.0.*
   twine upload dist/*
   ```
   Verify: `pip install synapsek-claims --dry-run` from a clean venv, or
   `pip download synapsek-claims`.
5. **Key ceremony (optional but recommended)**: publish the trusted issuer
   public key + the exact `svc verify` commands as a repo page or
   `TRUST.md`, so buyers know which key to trust and how to get it out-of-band
   (this file itself is that artifact: `examples/trusted-issuer.pub`).
6. **Announce** (1 min): one-paragraph blurb — "verified claims for AI
   artifacts; one command re-derives the numbers" + the two example links.

## Non-goals for v0.1.0 (do not promise in the announcement)

- No public registry *service* yet (the registry is a portable JSON file;
  endpoint comes later).
- No GPU/CPU cross-device tolerance guarantees (example 1's rerun is
  CPU-bit-exact on the pinned env; other envs may need a documented tolerance).
- No agent-execution attestation yet (roadmap, v0.2+).

## Rollback

Unpublish is one `twine`/GitHub action per surface; the tag is the anchor.
Nothing here touches the RunPod pod, the compiler key, or any model weights
beyond the one example artifact.
