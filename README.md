<div align="center">

# synapsek-claims

**Verified claims for AI artifacts.**

*Don't take benchmark numbers on faith. Re-derive them — with one command.*

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]
[![Tests](https://img.shields.io/badge/tests-16_passing-brightgreen.svg)](tests)

</div>

---

## The problem

The AI industry runs on vendor-reported numbers. The uncomfortable,
well-documented facts:

- A large share of published model benchmarks is **vendor-reported, never
  independently re-run** — public analyses have found the majority of
  leaderboard entries with no third-party reproduction.
- Reproduction failures are not hypothetical: high-profile releases have
  shipped with benchmark scores that could not be reproduced when
  re-measured (claims of ~57% vs ~33% measured on real suites).
- Integrity signing solved one narrow problem — *the bytes didn't change*.
  Nobody signs **quality claims**, and nobody can *prove a measured number
  re-derives* from pinned evidence.

`svc` (Synapsek Verified Claims) is the missing referee. It is a
framework-agnostic, cryptographically verifiable layer that signs **measured
quality claims** about any AI artifact or pipeline — and lets a buyer
**re-derive every number with one command**.

## What one command does

```
$ svc verify claim.json --trusted-pubkey trusted-issuer.pub --base-dir . --rerun
=== SVC VERIFY synapsek.claim/knowledge-encoder-dedup/v3b-seed1 ===
  [PASS] L1 authenticity: valid
  [PASS] L2 integrity: 10 files match
  [PASS] L3 evidence: 2 traces match
  [PASS] L4 soundness: 1/1 values recomputed
  [PASS] L4b rerun: 1 claims re-executed
  [PASS] L5 claims: statuses + recommendations re-derived
  claim dedup_spearman: value=0.4172424238214698 recomputed=0.4172424238214698 status=proven [OK]
RESULT: PASS — all layers verified; claims re-derived
```

That is the entire buyer workflow. Exit code `0` = the numbers are real.

## The five layers

```
                         svc verify
                            │
   L1  AUTHENTICITY      Ed25519 signature valid — and the issuer's key
                         is exactly the key you trust (no rogue self-issuance)
                            │
   L2  INTEGRITY         every pinned file re-hashed: weights, code,
                         data, attestation documents
                            │
   L3  EVIDENCE          every evidence trace re-hashed + Merkle-rooted,
                         item count checked — one swapped row fails this
                            │
   L4  SOUNDNESS         every claimed value recomputed FROM THE EVIDENCE
                         by its documented derivation rule
                            │
   L4b RE-EXECUTION      (opt-in --rerun) the pinned evaluation re-runs;
                         its output is compared within the claim's tolerance
                            │
   L5  CLAIMS            every pass/fail status re-derived from
                         value + threshold; the "recommended for" list is
                         re-derived from the proven labels
```

If the issuer claimed more than the numbers support, **verification fails** —
at a specific layer, with the specific reason. That last property,
anti-overclaiming by construction, is what makes this different from a signed
eval dashboard.

| You worry about… | The layer that stops it |
|---|---|
| claim edited after signing (value, status, threshold) | L1 |
| rogue issuer self-attesting under its own new key | L1 |
| weights / code / data swapped in the claim dir | L2 |
| evidence trace edited, reordered, truncated | L3 |
| claimed value not supported by its own evidence | L4 |
| number not reproducible by re-running the pinned eval | L4b |
| "proven" claimed below the documented threshold | L5 |
| a not-proven label quietly added to "recommended for" | L5 |
| claim circulated that was never registered | `--registry` |

## Quickstart

```bash
pip install synapsek-claims

# buyer
svc verify examples/pipeline-dedup/claim.json \
    --trusted-pubkey examples/trusted-issuer.pub \
    --base-dir examples/pipeline-dedup --rerun

# issuer
svc keygen --out-dir ./keys
svc attest skeleton.json --key ./keys/issuer_ed25519 --base-dir ./claimdir
svc registry add registry.json --claim ./claimdir/claim.json --issuer-id you
```

Machine-readable reports: `svc verify ... --json`. Exit code `0` = PASS,
`1` = FAIL.

## What a claim is

A claim is a signed JSON document:

- **subject** — what it's about: files (hashed) + evidence traces
  (hashed + Merkle-rooted, one JSON item per line);
- **pinned** — the environment, dataset, and config the measurement used;
- **claims** — each with a metric, a measured `value`, a documented
  `threshold`, a derived `status` (`proven` / `not_proven`), and a
  `derivation` rule telling the buyer how to recompute it;
- **recommendation** — labels the numbers support, and labels they don't;
- **disclosures** — honest limitations, in writing;
- **signature** — Ed25519 over the canonical form of all of the above.

Derivation rules are a tiny grammar with **no hidden code**:

| rule | recomputation |
|---|---|
| `field:<name>\|mean` / `field:<name>\|last` | aggregate a field over the evidence trace |
| `file:<path>#<field>` | read a field from a pinned JSON file |
| `script:<path>#<id>` | run the issuer's pinned eval; compare `id` from its final JSON stdout |
| `attested:<json.path>` | read a value from a pinned attestation document |

`script:` is the only rule that executes anything — it is the issuer's pinned
evaluation, fully visible to the buyer, and it runs only when the buyer
passes `--rerun`. You read it before it can ever run.

## Two working examples (real, measured, verify PASS as shipped)

**`examples/pipeline-dedup`** — a knowledge encoder (2-layer transformer +
Perceiver resampler, K=128 latents) claiming Spearman **0.4172** between
latent similarity and token Jaccard over a pinned 100-doc holdout (4,950
pairs, row-by-row evidence). `--rerun` re-executes the pinned eval on CPU and
reproduces the value **bit-exactly** (tolerance 1e-6, observed drift 0).

**`examples/cartridge-v11`** — the Synapsek knowledge cartridge v1.1 wrapped
through the same pipeline: 13 claims. The 4 v0 gist dimensions are recorded
as **`not_proven`** — below the pre-registered bars (topic 22.67 vs ≥50,
dedup 0.122 vs ≥0.4, retrieval 9.33 vs ≥25, summarize 0.123 vs ≥0.2). An
honest claim is allowed to say *no*; the system enforces that it actually
means it. The 9 QA-fidelity claims are `proven`, re-derived from pinned
per-item traces — including cross-family results: a 7B model decoding latents
produced by a small encoder (8.37 / 6.58 / 7.55 F1 across seeds).

```
$ svc verify examples/cartridge-v11/claim.json --trusted-pubkey ... --base-dir .
  [PASS] L1 authenticity: valid
  [PASS] L2 integrity: 1 files match
  [PASS] L3 evidence: 6 traces match
  [PASS] L4 soundness: 13/13 values recomputed
  [PASS] L5 claims: statuses + recommendations re-derived
  claim gist_topic: value=22.67 recomputed=22.67 status=not_proven [OK]
  claim qa_qwen_s1: value=0.097809 recomputed=0.0978094028382634 status=proven [OK]
  claim qa_7b_s3: value=7.55 recomputed=7.55 status=proven [OK]
RESULT: PASS — all layers verified; claims re-derived
```

## Trust model

- **Ed25519** over deterministic canonical bytes (sorted keys, compact JSON).
  Same byte format as the Synapsek v1.1 attestation engine — the two
  ecosystems interoperate.
- Only the **public** key ships with claims. Buyers trust a public key held
  **out-of-band** (`examples/trusted-issuer.pub`, or the v1.1 attestation
  bundle); a claim cannot choose its own trusted key.
- The **registry** (`registry/registry.json`) is a plain-JSON trust anchor:
  claim id → issuer key → claim hash. Portable today, a hosted endpoint
  later. See `examples/TRUST.md`.
- Every layer reports independently: a failure names the layer, the file,
  the claim, and the reason.

## What this is — and is not

| | |
|---|---|
| ✅ Signs **quality claims** and proves they re-derive | ❌ Not a model-signing replacement — OpenSSF/Sigstore-style integrity signing is a commodity and a good one; SVC is complementary |
| ✅ Pins *your* evaluation; structurally hostile to fudging | ❌ Not a benchmarking service — it cannot make a bad number look good |
| ✅ `proven` = reproducible from pinned evidence at/above the documented threshold | ❌ Not a quality certifier — the threshold is the issuer's disclosed commitment; the buyer judges it |

## Roadmap

- [x] claim schema v0.1, 5-layer verify, pinned re-run engine, registry, CLI
- [x] two attested real-world examples, 16-test suite, Apache-2.0
- [ ] public registry endpoint + claim URI scheme
- [ ] verifiable agent-execution records (tool calls, approvals, audit logs as evidence)
- [ ] batch verify; GPU/CPU cross-device tolerance policies

## Security & contributing

Found a verification bypass? Read **[SECURITY.md](SECURITY.md)** before
reporting. Contribution guidelines in **[CONTRIBUTING.md](CONTRIBUTING.md)**.

Design rationale and threat model: **[docs/DESIGN.md](docs/DESIGN.md)**.
Release/publish runbook: **[RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)**.

## Tests

```bash
python3 -m pytest tests/ -q    # 16 tests: roundtrip, tamper L1/L2/L3/L4b/L5,
                                # rogue issuer, overclaim, registry, canonical
```

## License

[Apache-2.0](LICENSE) © Synapsek Labs
