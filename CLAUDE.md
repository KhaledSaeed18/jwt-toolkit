# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`jwt-toolkit` — a defensive Click-based CLI for inspecting, verifying, auditing, forging (for self-audit), and cracking JSON Web Tokens. Output is meant to reflect the **security outcome**, not the technical event.

Responsible-use framing: only run `crack`, `forge`, and `audit` against tokens and systems the user is authorized to test. Keep that posture in command help text, errors, and any new user-facing strings.

## Toolchain

- Python **3.13+** only (no backcompat shims).
- Package manager: **`uv`** (not pip directly). Lockfile is `uv.lock`.
- Build backend: `hatchling`. Entry point: `jwt-toolkit = "jwt_toolkit.cli:cli"`.
- All workflows go through the `Makefile` — prefer `make <target>` over invoking tools directly so config (severity levels, parallelism, coverage thresholds) stays consistent.

## Commands

```
make install      # uv sync --group dev + pre-commit install
make fmt          # ruff format + ruff check --fix
make lint         # ruff format --check + ruff check (no fixes)
make typecheck    # mypy (strict mode)
make test         # pytest --cov -n auto  (coverage gate: 80%)
make test-fast    # pytest -n auto, no coverage
make security     # bandit (medium+)
make audit        # pip-audit
make check        # lint + typecheck + test + security + audit  ← full CI gate
make pre-commit   # pre-commit on all files
```

**Before declaring non-trivial work done, run `make check`.** It mirrors CI; if it passes locally, CI will pass.

Single test: `uv run pytest tests/test_cmd_decode.py::test_name`.

## Testing quirks

- `xfail_strict = true` — an `xfail` test that unexpectedly passes is a failure. Remove the decorator when fixing the underlying issue.
- `filterwarnings = error` — any warning fails the test. Don't suppress; fix the cause.
- Coverage `fail_under = 80`. `jwt_toolkit/cli/banner.py` is excluded (pure UX).
- Tests run in parallel (`-n auto`) — don't rely on shared mutable state, working directory, or test-order.

## Layout

- `jwt_toolkit/cli/` — Click group, banner, console (rich), shared panel/decoding helpers.
- `jwt_toolkit/commands/` — one module per subcommand. New commands go here and must be imported + registered in `jwt_toolkit/cli/__init__.py`.
- `jwt_toolkit/core/` — JWT parsing, crypto, auditor, forger, cracker. CLI commands should stay thin; logic belongs in `core/`.
- `tests/` — `test_cmd_*.py` for command surface, `test_*.py` for core. Shared fixtures in `conftest.py`, helpers in `helpers.py`.
- `wordlists/common-secrets.txt` — bundled wordlist for `crack`.

## CLI conventions

- Global flags `--no-banner`, `--quiet`, `--no-color` exist for scripting. Env equivalents: `JWT_TOOLKIT_QUIET=1`, `NO_COLOR=1`. Any new command must respect them (use the existing `console` helpers — don't `print()` directly).
- Comments: plain single-line `#` only. No banner/divider comment blocks.
- Don't add comments that just restate the code. Only write a comment when the *why* is non-obvious.

## Release

Version lives in `pyproject.toml`. Tag a release and publish via GitHub Releases — `publish.yml` builds with `uv build` and uploads to PyPI via Trusted Publishing (OIDC, `pypi` environment with manual approval). Don't publish manually with twine.
