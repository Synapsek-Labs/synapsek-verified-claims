# Security policy

`svc` exists to prevent exactly the kind of thing a security bug in it would
enable: a verification layer that can be bypassed destroys the trust of
every claim it signs. We treat such bugs as **critical**.

## What counts as a vulnerability

- any input under which `svc verify` returns PASS while a layer's stated
  guarantee is violated (signature bypass, hash bypass, Merkle bypass,
  status/recommendation re-derivation error, registry-hash mismatch);
- a derivation rule that can execute code it was not documented to execute;
- a way to make `svc attest` seal a claim whose status does not follow from
  value + threshold;
- key-custody issues: private key material exposed in any shipped artifact,
  sdist, wheel, or repo path.

## Reporting

Report privately before any public disclosure:

- Open a **private** security advisory:
  `https://github.com/Synapsek-Labs/synapsek-verified-claims/security/advisories/new`
  (GitHub secret reporting; if unavailable, email the organization owner —
  contact via the Synapsek Labs org page).
- Please include: the claim or input, the command that produced the
  incorrect PASS/FAIL, and the layer you believe is bypassed.

We aim to acknowledge within 48h and to ship a fix or a written rationale.
No credit required; credited with permission by default.

## Scope notes (not vulnerabilities)

- A buyer running a `script:` rule they did not read: by design — the script
  is pinned and visible; `--rerun` is explicit.
- A threshold chosen to be trivially low: disclosed in the claim; the buyer
  judges it. The system guarantees consistency, not ambition.
- Cross-device float drift beyond a claim's stated tolerance: document a
  tolerance in the claim; do not file as a bypass.

## Auditing

The threat model and the layer-by-layer failure table are in
[docs/DESIGN.md](docs/DESIGN.md). The test suite (`tests/`) covers tamper at
every layer plus regression tests for each 2026-10-17 independent-audit
finding (execution consent gates, no-shell execution, status from
recomputed value, finite guards, manifest/path-escape guards, UTF-8); new
bypass classes should add a regression test.

## Audit history

- **2026-10-17** — independent audit of v0.1.0 confirmed working
  verification and found: (1) script execution reachable without `--rerun`
  and after layer failures, via a shell command string; (2) claim status
  derived from the claimed value rather than the recomputed one, with
  NaN tolerances disabling checks; (3) `file:` derivation inputs not
  required to be manifest-pinned; (4) README overstatement; (5)
  quickstart/reproducibility gaps. All fixed in **v0.1.1** with regression
  tests (`tests/test_audit_fixes.py`). The auditor's suggested positioning
  — "portable AI evaluation receipts: verify who issued a result, which
  evidence supports it, and whether you can reproduce it" — is adopted.
