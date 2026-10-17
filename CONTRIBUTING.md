# Contributing

Thanks for looking at synapsek-claims. The project is small on purpose; keep
it that way.

## Ground rules

1. **Verification semantics are the product.** Changes to `src/svc/verify.py`,
   `schema.py`, `rules.py`, or `claim.py` need an explanation of exactly which
   threat each line defends, and a regression test in `tests/` that fails
   without the change.
2. **No code execution inside derivation rules.** The rule grammar stays
   declarative; `script:` is the single, buyer-visible, buyer-triggered
   exception. Do not widen it.
3. **Honest defaults.** Statuses are always re-derived from value +
   threshold; recommendations are always re-derived from statuses. Anything
   that lets an issuer hand-pick a `proven` status is out of scope.
4. **Small surface.** The package depends on `cryptography` only. Do not add
   runtime dependencies without a written justification in the PR.

## Development

```bash
pip install -e ".[test]"
python3 -m pytest tests/ -q        # must stay green
python3 -m compileall -q src
```

For schema changes: bump `svc_version`, keep old claims verifiable by old
code (read-side compatibility), and update `docs/DESIGN.md` in the same PR.

## Process

- Fork, branch, PR. PRs that change verify semantics include a before/after
  `svc verify` transcript on a tampered claim.
- Conventional commit messages are appreciated, not required.
- We review for threat-model fit before code style.
