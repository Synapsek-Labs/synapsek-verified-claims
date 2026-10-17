# Examples

Two real, sealed, verifiable claims. Both verify PASS as shipped.

## pipeline-dedup

A knowledge encoder (2-layer 256-d transformer + Perceiver resampler,
K=128 latents) attesting document-duplicate-detection fidelity:

- claim: `dedup_spearman` = 0.4172424238214698 (threshold ≥ 0.40, pre-registered)
- evidence: 4,950 doc-pair rows (latent cosine + token Jaccard per pair)
- rerun: `python3 code/eval_dedup.py` — deterministic, CPU-only,
  reproduces the value bit-exactly on the pinned environment

```bash
cd examples/pipeline-dedup
svc verify claim.json --trusted-pubkey ../trusted-issuer.pub --base-dir . --rerun
```

**Note:** `artifact/encoder.pt` (160 MB) is distributed as a GitHub release
asset (v0.1.0), not in git. Fresh clones must fetch it before verify (L2 will
report it missing otherwise):

```bash
cd examples/pipeline-dedup
mkdir -p artifact
curl -L -o artifact/encoder.pt \
  "https://github.com/Synapsek-Labs/synapsek-verified-claims/releases/download/v0.1.0/encoder.pt"
```

(The pinned tokenizer files under `code/tokenizer/` are committed.)

`--rerun` re-executes the pinned eval, which needs the pinned environment's
ML deps: `torch` (CPU) + `transformers`, matching the claim's `pinned.environment`
block. On a machine without them, verification still runs — but L4b reports
the re-execution failure explicitly (e.g. `ModuleNotFoundError: No module
named 'torch'`) while all other layers (signature, integrity, evidence,
recompute, claims) are still evaluated. That is honest failure, not a silent
pass: the numbers still re-derive from evidence; only the re-execution is
skipped-by-environment, and the report says so.

## cartridge-v11

The Synapsek knowledge cartridge v1.1 wrapped through the same pipeline:

- 4 gist claims — all `not_proven` (below pre-registered bars; the honest "no")
- 6 QA-fidelity claims re-derived from pinned per-item traces
  (Qwen2.5-1.5B and SmolLM2-1.7B, hotpotqa, 100 items/seed)
- 3 cross-family claims (Qwen2.5-7B-Instruct decoding the same latents)

```bash
cd examples/cartridge-v11
svc verify claim.json --trusted-pubkey ../trusted-issuer.pub --base-dir .
```

No `--rerun` here: this claim re-derives from evidence (no local model
execution needed). Full model-level regeneration is documented in the v1.1
attestation's G4 clean-room buyer report.

## Trust anchor

`trusted-issuer.pub` is the public key for issuer `synapsek.compiler/v1` —
see [TRUST.md](TRUST.md). Obtain it out-of-band; never take the trusted key
from a claim document.
