---
name: new-command
description: Scaffold a new Click subcommand for jwt-toolkit. Creates `jwt_toolkit/commands/<name>.py`, registers it in `jwt_toolkit/cli/__init__.py` (import + `add_command` + aligned `CLI_HELP` entry), and creates a matching `tests/test_cmd_<name>.py`. Enforces the project's CLI, secret-handling, and `--json` conventions. Use only when adding a new top-level `jwt-toolkit <verb>` command.
disable-model-invocation: true
---

# /new-command — scaffold a CLI subcommand

`$ARGUMENTS` is the command name. Accept kebab-case (`refresh-token`) or snake_case (`refresh_token`). Module file uses snake_case; the Click command's `name` attribute determines the CLI name — set it explicitly to the kebab-case form to avoid implicit conversion surprises.

## Step 0 — Confirm scope

**Do not scaffold blind.** Before writing files, get one short sentence from the user covering:

1. What's the security outcome? (One line that could go in the help string.)
2. What inputs does it take? Token? Key/secret? Wordlist? JWKS URL? Other.
3. Does it produce structured output? If yes, `--json` is required.
4. Does it talk to the network? If yes, the only acceptable destination is a JWKS endpoint via `jwt_toolkit.core.jwks` — confirm.
5. Is it read-only inspection, mutation (mint/forge), or attack-surface (crack)? This drives default flags and help-text voice.

If any answer is "I'm not sure", stop and ask the user. Scaffolding is cheap to redo but expensive to undo after tests reference it.

## Step 1 — Validate the name

- Must match `^[a-z][a-z0-9-]*$` (kebab) or `^[a-z][a-z0-9_]*$` (snake). Reject anything else with a one-line error.
- Must not collide with an existing command. Read `jwt_toolkit/cli/__init__.py` first — if the name is taken, stop.

## Step 2 — Write `jwt_toolkit/commands/<snake_name>.py`

Mirror the shape of `decode.py` / `verify.py`. Required surfaces:

```python
import json

import click

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION
# Plus any core helpers the command needs — keep logic in core/, not here.


@click.command(
    name="<kebab-name>",
    help="<one-sentence security outcome>.",
)
@click.argument("token")  # or @click.option(...) — see rules below
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON output.")
def <snake_name>(token: str, as_json: bool) -> None:
    # 1. Resolve / validate inputs. Raise click.ClickException on user error.
    # 2. Call into jwt_toolkit.core.<...> for the actual work.
    # 3. If --json: click.echo(json.dumps({"schema_version": JSON_SCHEMA_VERSION, ...}, indent=2))
    # 4. Else: render via console / panels.
    ...
```

### Hard rules

- **Never `print()`.** Always `console.print(...)` for human output, `click.echo(...)` for `--json` payloads. `print` bypasses `--quiet`, `--no-color`, and the project's rich console wiring.
- **`--json` payloads MUST include `"schema_version": JSON_SCHEMA_VERSION`** as the first key. Field names are part of the public API — pick them carefully and document them in the docstring.
- **Secrets and keys are options, never positional arguments.** `--secret`, `--private-key`. Positional shows up in shell history and `ps`. Don't echo their values in errors; refer to the flag name only.
- **Errors raise `click.ClickException("...")`** with a one-sentence user-facing message. Deeper layers raise from `jwt_toolkit.core.errors`; translate them at the command boundary.
- **Help-text voice matches the rest of the CLI.** One short sentence, security-outcome shaped, no implementation detail. ("Verify the signature and standard claims of a JWT." — not "Calls cryptography library to check signature.")
- **No new dependencies.** If you think you need one, stop and ask the user — every new dep has to be justified per `CONTRIBUTING.md`.
- **Logic belongs in `core/`.** If the command module exceeds ~60 lines of non-flag-parsing code, you're doing too much here. See `jwt_toolkit/core/CLAUDE.md`.

## Step 3 — Register in `jwt_toolkit/cli/__init__.py`

Three edits, all needed:

1. **Import** alongside the other command imports (alphabetical):
   ```python
   from jwt_toolkit.commands.<snake_name> import <snake_name>
   ```
2. **Register** next to the other `cli.add_command(...)` calls (alphabetical):
   ```python
   cli.add_command(<snake_name>)
   ```
3. **`CLI_HELP` block** — add a line under `Commands:` matching the **exact column alignment** of existing entries. After editing, count columns: command name is left-justified in a fixed-width field, followed by two spaces, followed by the description. Verify alignment by reading the file back; if your line drifts, fix it.

Don't reorder existing entries. Append in the conventional place (alphabetical within the block, unless the existing order is grouped by purpose — match what's there).

## Step 4 — Write `tests/test_cmd_<snake_name>.py`

Use Click's `CliRunner` — see `tests/test_cmd_decode.py` for the shape. Required coverage:

- **Happy path** — typical valid input, asserts on exit code 0 and a stable substring of output.
- **Error path** — at least one — invalid input (bad token, missing required option, mutually exclusive flags). Asserts exit code 1 (or 2 for usage errors) and a quoted error message.
- **`--json` shape** (if applicable) — invoke with `--json`, parse stdout as JSON, assert `schema_version == "0.1"` (read the constant, don't hardcode) and assert on the field names you've committed to as public API.
- **No network.** If the command touches JWKS, use the offline fixtures in `tests/conftest.py` / `tests/helpers.py`. Network in tests fails CI under `filterwarnings = error` and is forbidden per `CLAUDE.md`.

Tests run in parallel (`-n auto`). No shared mutable state, no `os.chdir`, no env-var leaks — use `tmp_path` and `monkeypatch`.

## Step 5 — Verify

Run in this order:

```sh
make fmt
make lint
make typecheck
uv run pytest -n auto tests/test_cmd_<snake_name>.py
make test         # ensure coverage stays ≥ 80
```

Then run `/check` (the full gate) before handing off. If coverage on the new module is below the threshold, add tests; do not exclude the file.

## Step 6 — Do not

- Do not bump the version. Releases are a separate `/release` workflow.
- Do not edit `CHANGELOG.md` (if present) unless the user asks — that often happens during release.
- Do not add `# type: ignore`, `# noqa`, or `# nosec` to make checks pass. If you're tempted, you're working around a real issue.
- Do not add the command to README.md without user confirmation — the README has its own structure and tone.
