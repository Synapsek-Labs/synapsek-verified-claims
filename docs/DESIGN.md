# SVC design notes (schema v0.1)

## Threat model

Attacker/defect goals, and the layer that stops each:

| threat | stopped by |
|---|---|
| claim document edited after signing (value, status, threshold) | L1 (signature) |
| issuer swap (rogue key self-attesting) | L1 (`issuer.public_key` must equal trusted key) |
| artifact/weights/code replaced in the claim dir | L2 (per-file sha256) |
| evidence trace edited, reordered, truncated | L3 (file sha256 + item count + Merkle root) |
| claimed value not actually supported by the evidence | L4 (value recomputed from evidence by the derivation rule) |
| claimed value not actually reproducible by re-executing the pinned eval | L4b (`--rerun`) |
| status overstated vs value+threshold | L5 (status re-derived) |
| recommendation includes a not-proven label / omits a not-proven label | L5 (recommendation set re-derived) |
| claim circulated that was never registered | `--registry` hash match |

What the layers do **not** stop: a buyer running a `script:` rule whose
contents they did not read; an evaluation script that measures something
different from what the metric name implies (mitigation: the script is pinned,
visible, and small by convention); a threshold chosen to be trivially low
(mitigation: it is disclosed and the buyer judges it).

## Canonical form

`canonical_bytes(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False).encode("utf-8")`. The signature covers everything except
the `signature` field itself. Same byte format as the Synapsek v1.1
attestation engine — an SVC claim and a v1.1 attestation over the same JSON
object share canonical bytes, so the ecosystems interoperate.

## Evidence model

Evidence is JSONL (one JSON object per line; a single-line JSON file is a
valid 1-item trace). Each trace carries `sha256` (whole file), `n_items`, and
`merkle_root` (order-sensitive: leaf = sha256(canonical(item)), odd nodes
duplicated). Per-item traces (e.g. one row per doc pair, or one row per QA
item) give the buyer auditable granularity; the Merkle root makes even a
single swapped row visible.

## Claim lifecycle

1. **measure** — issuer runs the pinned eval on the pinned dataset/artifacts;
   the eval writes evidence traces (per-item rows) and prints the summary.
2. **seal** — `svc attest` fills every file hash, trace hash, Merkle root and
   item count from disk, re-derives every claim `status` from `value` +
   `threshold` (the skeleton's status is overwritten — the issuer cannot
   hand-pick), hashes the config, and signs.
3. **register** — `svc registry add` stores claim id → issuer key → claim
   hash. The registry file is plain JSON and portable (same shape as the v11
   attestation registry).
4. **verify** — `svc verify` (buyer). With `--registry`, the claim document is
   first matched against the registry entry, then the 5 layers run. With
   `--rerun`, pinned eval commands are re-executed and their outputs compared
   within the claim's tolerance.

## Rule grammar (deliberately tiny)

No code evaluation inside rules. Four forms (see README table). `script:`
runs `python3 <path>` with cwd = claim dir and a timeout; its **final stdout
line must be one JSON object** and the named field must be numeric. This
keeps the recompute path auditable: the buyer sees exactly which file runs,
with which cwd, and what field is compared.

## Recommendation semantics

- `recommended_for` must **exactly** equal the sorted set of labels of
  proven claims (over-recommending fails, under-recommending fails);
- `not_recommended_for` must be a **superset** of the labels of not-proven
  claims (extra entries allowed — use them for honest scope limits).

This is the anti-overclaiming core: a vendor cannot ship a claim whose
numbers fail its own thresholds while still marketing the label.

## Scale honesty

Values and thresholds live in whatever scale the derivation rule produces.
If the evidence is 0-1 and the claim value is percent-based (or vice versa),
L4 fails — a good failure, because scale confusion is exactly how vendor
numbers get misread. Claim `unit` fields document the scale.

## Relationship to the v1.1 attestation

The cartridge attestation signs the whole cartridge qualification
(provenance, fidelity, 24 evidence traces). An SVC claim about the same
cartridge *wraps* it: the attestation document is a pinned file (role
`attestation`), `attested:` rules re-derive values from it, and QA-fidelity
claims re-derive directly from the same per-item traces. Chain of trust:
SVC claim → (hash) → v1.1 attestation → (hash) → weights.

## v0.2 ideas (not shipped)

- public registry endpoint + claim URI scheme
- verifiable agent-execution records (tool calls, approvals, audit log
  entries as evidence traces)
- batch verify (many claims, one report)
- tolerance policies for GPU/CPU drift
