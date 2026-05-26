---
name: check
description: Run the full CI gate (`make check` — lint + typecheck + test + security + audit) and report per-stage pass/fail with triage. Use before declaring non-trivial work done, before pushing, before opening a PR, or whenever the user asks "is this ready?".
---

# /check — full CI gate

`make check` is the contract this repo enforces: if it passes locally, CI passes. Never partial-run, never skip stages, never `# noqa` your way past a failure.

## What it runs (in order)

1. **lint** — `ruff format --check` then `ruff check` (no fixes). Fail = formatting drift or a lint rule violation.
2. **typecheck** — `mypy` in strict mode. Fail = a real type error.
3. **test** — `pytest --cov -n auto`, `fail_under = 80`, `xfail_strict = true`, warnings as errors. Fail = bad test, coverage drop, surprise xpass, or surfaced warning.
4. **security** — `bandit` at medium+. Fail = a security-smell pattern landed (e.g., `assert` in non-test, `subprocess shell=True`, weak randomness).
5. **audit** — `pip-audit` against `uv.lock`. Fail = a known CVE in a pinned dependency.

## How to run

```sh
make check
```

Stream the output. Don't pipe through filters that suppress warnings — `filterwarnings = error` is on, warnings are real failures.

## Reporting

After it finishes, summarize per stage with a one-line verdict. Use `✅` and `❌` for fast visual scan, then quote the offending line and point at `file:line` for any failure:

- ✅ / ❌ **lint** — ruff
- ✅ / ❌ **typecheck** — mypy
- ✅ / ❌ **test** — pytest (note coverage % if reported)
- ✅ / ❌ **security** — bandit
- ✅ / ❌ **audit** — pip-audit

If every stage passes, that's the whole report. Don't pad it.

## Triage by stage

- **lint fail** — run `make fmt` **once** to auto-fix formatting and `--fix`-able rules, then re-run `make check`. If lint still fails, the remaining issues need real edits (unused imports, naming, etc.); fix them.
- **typecheck fail** — fix the type error. Don't reach for `# type: ignore` unless the user agrees. If you do add one, include the specific `[error-code]` and a one-line reason.
- **test fail** — read the failure. If it's a coverage drop below 80, add tests rather than tweaking the threshold or adding `pragma: no cover`. If it's an `xfail`-that-passed, remove the `xfail` decorator — the bug is fixed.
- **security fail** — surface the bandit finding (rule id + file:line). Don't suppress with `# nosec` without user okay; a finding is a question the author needs to answer.
- **audit fail** — print the CVE and affected package. Resolution is usually a `uv lock --upgrade-package <name>`; confirm with the user before bumping.

## Anti-patterns to refuse

- `make test` instead of `make check` to call something "done".
- Removing files from coverage to dodge the 80% gate.
- Editing `pyproject.toml` to relax ruff/mypy/bandit/coverage thresholds without the user explicitly asking.
- Re-running until a flaky test passes. Tests run in parallel — flakes mean state leaked between tests; find it.

## Coverage artifact

Coverage XML is written to `coverage.xml` at the repo root (CI uploads it as an artifact). If a stakeholder asks "what's covered?", point at that file rather than re-running with different flags.
