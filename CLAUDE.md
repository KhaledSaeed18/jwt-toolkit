# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`jwt-toolkit` is a **defensive** Click-based CLI for inspecting, verifying, auditing, forging (for self-audit), and brute-forcing weak HMAC secrets on JSON Web Tokens. It is published to PyPI and installed by external users — treat it as a public-API library wrapped in a CLI, not as an internal script.

**Threat-model framing.** `audit`, `forge`, and `crack` exist so an operator can find weaknesses in tokens and systems they own before an attacker does. Every user-facing string — help text, error messages, panel titles — should reinforce that posture. Output is meant to reflect the **security outcome**, not the technical event ("Signature did not verify — token is not trustworthy", not "HMAC mismatch at byte 0x20"). Never echo a user's `--secret` or private key in messages, banners, debug output, or exceptions.

## Toolchain

- Python **3.13+ only**. No backcompat shims, no `__future__` imports.
- Package manager: **`uv`**. Lockfile is `uv.lock` — commit changes to it whenever you touch dependencies.
- Build backend: `hatchling`. Entry point: `jwt-toolkit = "jwt_toolkit.cli:cli"`.
- All workflows go through the `Makefile` — prefer `make <target>` over invoking tools directly so config (severity levels, parallelism, coverage threshold) stays consistent.

## Commands

```sh
make install      # uv sync --group dev + pre-commit install
make fmt          # ruff format + ruff check --fix
make lint         # ruff format --check + ruff check (no fixes)
make typecheck    # mypy (strict mode)
make test         # pytest --cov -n auto  (coverage gate: 80%)
make test-fast    # pytest -n auto, no coverage
make security     # bandit (medium+)
make audit        # pip-audit
make check        # lint + typecheck + test + security + audit   ← full CI gate
make pre-commit   # pre-commit on all files
```

**Before declaring non-trivial work done, run `make check`.** It mirrors CI; if it passes locally, CI will pass. Don't skip stages, don't pass `--no-verify`, don't add `# type: ignore` or `# noqa` without surfacing it to the user.

Single test: `uv run pytest tests/test_cmd_decode.py::test_name`. Run one file with coverage off (`make test-fast -- tests/test_cmd_decode.py`) when iterating.

## Layered architecture (load-bearing)

```text
jwt_toolkit/
├── cli/         # Click plumbing only — banner, console, panels, decoding helpers.
├── commands/    # One file per subcommand. THIN. Parse flags, call core, render via console/panels.
└── core/        # Pure logic. NO Click, NO Rich, NO I/O beyond explicit file/HTTP helpers.
                 # See jwt_toolkit/core/CLAUDE.md for crypto invariants.
```

Commands stay thin: they translate flags → core inputs, call into `core/`, then format results. New logic belongs in `core/`. If you find yourself importing `click` or `rich` inside `core/`, stop — that's a layering violation.

## Public surfaces (treat as API; bump carefully)

Three things are observable by downstream users and break things when you change them silently:

1. **The CLI grammar** — command names, flag names, flag semantics. Renames or removals are breaking changes; add an alias before removing, or wait for a major version.
2. **`--json` output shape.** Every command that supports `--json` includes `schema_version` (currently `"0.1"`, defined in `jwt_toolkit/cli/decoding.py`). **If you change a field name, type, or remove a field, bump `JSON_SCHEMA_VERSION`** and call it out in the PR. Adding new optional fields is non-breaking.
3. **Stable error codes** — `core/errors.py` exceptions carry a machine-readable `code`. `--json` consumers key off these. Codes are forever; pick a new one rather than reusing or renaming an existing one.

Exit codes follow Click defaults: `0` = success, `1` = command-handled failure (`click.ClickException`), `2` = usage error (Click's own). Don't `sys.exit(N)` directly; raise `click.ClickException` so the message is rendered through the project's console.

## CLI conventions

- **Never `print()`.** Use `from jwt_toolkit.cli.console import console` (and `click.echo` for `--json` payloads). `print()` bypasses `--quiet`, `--no-color`, and the `JWT_TOOLKIT_QUIET=1` / `NO_COLOR=1` env vars.
- Global flags `--no-banner`, `--quiet`, `--no-color` exist for scripting. Any new command must respect them.
- Secrets and keys: accept them as `--secret` / `--private-key`. **Never accept secrets as positional arguments** (they show up in shell history and `ps`). Don't echo their values in errors — refer to them by flag name only.
- Errors are `raise click.ClickException("user-facing sentence")` from the command layer; deeper layers raise domain exceptions from `core/errors.py`. The CLI translates the latter into the former.
- Match the help-text voice of existing commands: one short security-outcome sentence, no implementation detail.
- When registering a new command, add it to the `Commands:` block in `jwt_toolkit/cli/__init__.py`'s `CLI_HELP` with the **same column alignment** as the existing entries.

## Code style

- Plain single-line `#` comments only. No banner/divider blocks, no section headers in comments.
- Comments are rare. Write one only when the *why* is non-obvious (hidden constraint, RFC reference, workaround for a specific bug). Don't explain *what* — names and types do that.
- Ruff is the source of truth: line length 100, Python 3.13 target, the curated ruleset in `pyproject.toml`. Don't argue with it; run `make fmt`.
- mypy runs in strict mode. New code adds type hints to every public function. `# type: ignore` requires a `[error-code]` and a reason.

## Testing

- `xfail_strict = true` — an `xfail` that unexpectedly passes is a failure. Remove the decorator when fixing the underlying issue.
- `filterwarnings = error` — any warning fails the test. Don't suppress; fix the cause.
- Coverage gate: 80%. `jwt_toolkit/cli/banner.py` is excluded (pure UX). Don't add new exclusions to dodge the gate.
- Tests run in parallel (`-n auto`) — no shared mutable state, no cwd dependence, no test-order coupling.
- CLI tests live in `tests/test_cmd_*.py` and use Click's `CliRunner`. Core tests live in `tests/test_<module>.py` and exercise pure functions without going through the CLI.
- Every new command needs at minimum: happy path, error path, and `--json` shape test if it supports `--json`.
- **No network in tests.** JWKS-using code paths must use the offline fixtures in `tests/conftest.py` / `tests/helpers.py`.

## Release

Version lives in `pyproject.toml`. Tag a release and publish via GitHub Releases — `.github/workflows/publish.yml` builds with `uv build` and uploads to PyPI via Trusted Publishing (OIDC, `pypi` GitHub environment with manual approval). **Never publish manually with `twine`/`uv publish`.** Full release flow is in the `/release` skill at `.claude/skills/release/SKILL.md`.

## Further reading

- @CONTRIBUTING.md — branch naming, commit conventions, PR checklist, full contributor flow.
- @jwt_toolkit/core/CLAUDE.md — crypto, parsing, and error-model invariants for the `core/` package.
