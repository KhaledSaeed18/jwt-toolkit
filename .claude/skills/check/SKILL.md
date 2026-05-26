---
name: check
description: Run the full CI gate (`make check` — lint + typecheck + test + security + audit) and report per-stage pass/fail. Use before declaring non-trivial work done, or any time the user asks "is this ready to push?".
---

# /check — full CI gate

Run `make check` from the repo root. It chains: `lint`, `typecheck`, `test` (with coverage, fail_under=80), `security` (bandit), `audit` (pip-audit).

## How to run

```
make check
```

Stream output. Do not pipe through filters that hide warnings — `filterwarnings = error` is set, so warnings are real failures.

## Reporting

After it finishes, summarize per stage:

- ✅ / ❌ **lint** (ruff)
- ✅ / ❌ **typecheck** (mypy)
- ✅ / ❌ **test** (pytest + coverage)
- ✅ / ❌ **security** (bandit)
- ✅ / ❌ **audit** (pip-audit)

For any failure, quote the relevant lines and point at the file:line.

## On failure

- **lint**: try `make fmt` first — it auto-fixes most ruff issues. Re-run `make check` after.
- **typecheck**: fix the type error; don't add `# type: ignore` unless the user okays it.
- **test**: if coverage drops below 80, add tests rather than excluding files.
- **security/audit**: surface the finding and CVE link; don't suppress without user input.

Never use `--no-verify` or skip stages.
