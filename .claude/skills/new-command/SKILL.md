---
name: new-command
description: Scaffold a new Click subcommand for the jwt-toolkit CLI. Creates `jwt_toolkit/commands/<name>.py`, registers it in `jwt_toolkit/cli/__init__.py`, and creates a matching `tests/test_cmd_<name>.py`. Use when adding a new top-level command (e.g., `jwt-toolkit refresh`, `jwt-toolkit introspect`).
disable-model-invocation: true
---

# /new-command — scaffold a CLI subcommand

`$ARGUMENTS` is the command name. Accept either kebab-case (`refresh-token`) or snake_case (`refresh_token`). Module file uses snake_case; CLI name uses kebab-case (Click converts underscores in function names to hyphens automatically when the function is named with underscores).

## Steps

1. **Validate the name**: must match `^[a-z][a-z0-9_-]*$`. Reject anything else with a one-line error.
2. **Confirm scope** with the user in one sentence: what the command does, what arguments it takes, whether it needs a token / key / wordlist. Don't proceed without their answer — the scaffold should reflect intent, not guess.
3. **Create `jwt_toolkit/commands/<snake_name>.py`** using the pattern of existing commands (see `decode.py`, `verify.py` for shape). Required:
   - Import `from jwt_toolkit.cli.console import console`. Never `print()` directly — that breaks `--quiet`/`NO_COLOR`.
   - Use `@click.command(help="...")` with a one-line description that reflects the security outcome, not the technical event.
   - If it outputs structured data, add `--json` flag and emit `{"schema_version": JSON_SCHEMA_VERSION, ...}` via `click.echo(json.dumps(...))` — match `decode.py`.
   - Put any non-trivial logic in `jwt_toolkit/core/`, not in the command module. Commands stay thin.
4. **Register in `jwt_toolkit/cli/__init__.py`**:
   - Add `from jwt_toolkit.commands.<snake_name> import <snake_name>`.
   - Add `cli.add_command(<snake_name>)` next to the other `add_command` calls.
   - Add a line under the `Commands:` block in `CLI_HELP` matching the column alignment of the existing entries.
5. **Create `tests/test_cmd_<snake_name>.py`** using `CliRunner` (see existing `tests/test_cmd_*.py`). Cover at minimum: happy path, `--json` output if applicable, error case (missing arg / bad input).
6. **Run `make fmt && make lint && make test -- tests/test_cmd_<snake_name>.py`** to confirm the scaffold is clean and the new test passes.
7. **Do not bump the version** — that's a separate release step.

## Conventions to preserve

- Comments: plain `#` only, no banners.
- Comments are rare — only when *why* is non-obvious.
- Respect global flags via `console` helpers.
- Coverage must stay ≥ 80 — the new tests need to actually exercise the new code.
