---
name: new-command
description: Scaffold a new top-level Click subcommand for jwt-toolkit (the `jwt-toolkit <verb>` form, like `decode`, `audit`, `verify`). Creates `jwt_toolkit/commands/<name>.py`, registers it in `jwt_toolkit/cli/__init__.py` (import + `add_command` + aligned `CLI_HELP` entry), and writes a matching `tests/test_cmd_<name>.py`. Enforces the project's CLI conventions: `console`-only output, secrets as options not positional args, typed `core/errors` raised and translated, `--json` payloads carrying `JSON_SCHEMA_VERSION`. Use this skill only for **new top-level verbs**. Don't use it for adding flags or behavior to an existing command, for creating subcommands under an existing group, or for refactors — edit the existing file directly.
disable-model-invocation: true
---

# /new-command — scaffold a CLI subcommand

`$ARGUMENTS` is the command name. Accept kebab-case (`refresh-token`) or snake_case (`refresh_token`). Module file uses snake_case; the Click command's `name` attribute determines the CLI name — set it explicitly to the kebab-case form to avoid implicit conversion surprises.

## Step 0 — Confirm scope

**Do not scaffold blind.** Before writing files, get a short sentence from the user covering:

1. **Security outcome** — one line that could go in the `help=` string. ("Reveal which JWKS endpoint a token claims it was signed by.")
2. **Inputs** — token? key/secret? wordlist? JWKS URL? File path? Stdin? Other.
3. **Structured output** — does it produce something a script would parse? If yes, `--json` is required and you must commit to a field set as public API.
4. **Network** — does it make HTTP calls? If yes, the only acceptable destination is a JWKS endpoint via `jwt_toolkit.core.jwks`. No other module is allowed outbound network. Confirm.
5. **Filesystem side effects** — does it write any file outside `tmp_path` in tests? Defaults must respect the user's cwd; never silently write into `$HOME`, `/tmp`, or other locations.
6. **Risk category** — read-only inspection (like `decode`, `audit`), mutation that produces output the user keeps (like `sign`, `forge`, `generate-secret`), or attack-surface (like `crack`). This drives default flags, help-text voice, and the inverted exit-code/color contract from [[project-jwt-toolkit]] if applicable.

If any answer is "I'm not sure", stop and ask. Scaffolding is cheap to redo but expensive to undo after tests reference it.

## Step 1 — Validate the name

- Must match `^[a-z][a-z0-9-]*$` (kebab) or `^[a-z][a-z0-9_]*$` (snake). Reject anything else with a one-line error.
- **Must not collide with an existing command.** Before proposing the name, run `awk '/^Commands:/,/^$/' jwt_toolkit/cli/__init__.py | grep -E '^\s+[a-z-]+'` to list current verbs. As of writing those are: `decode`, `sign`, `audit`, `verify`, `forge`, `crack`, `generate-secret`, `download-wordlists`. If the requested name matches or near-matches one of these, stop and ask the user to pick another or to edit the existing command directly.

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
- **Honor global flags** `--no-banner`, `--quiet`, `--no-color`, plus the env equivalents `JWT_TOOLKIT_QUIET=1` / `NO_COLOR=1`. Using `console.print(...)` and `click.echo(...)` (not bare `print`) is what makes this automatic — the `console` instance is wired up in `jwt_toolkit/cli/console.py` to read those signals. If you bypass `console`, you break scripting.
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
3. **`CLI_HELP` block** — add a line under `Commands:` matching the existing column alignment. Don't eyeball it. After editing, verify with:

   ```sh
   awk '/^Commands:/,/^$/' jwt_toolkit/cli/__init__.py | grep -E '^\s+[a-z-]+' | awk '{ printf "%2d  %s\n", length($1), $1 }'
   ```

   The widths should cluster — every command name shorter than the longest is left-justified in the same fixed field. If your new line's name is shorter than the longest and you wrote it with the wrong number of spaces, the description column drifts. Fix it before moving on; drift is visible to every CLI user forever.

Don't reorder existing entries. Append in the conventional place (alphabetical within the block, unless the existing order is grouped by purpose — match what's there).

## Step 4 — Write `tests/test_cmd_<snake_name>.py`

Use Click's `CliRunner` — see `tests/test_cmd_decode.py` for the shape. Required coverage:

- **Happy path** — typical valid input, asserts on exit code 0 and a stable substring of output.
- **Error path** — at least one — invalid input (bad token, missing required option, mutually exclusive flags). Asserts exit code 1 (or 2 for usage errors) and a quoted error message.
- **`--json` shape** (if applicable) — invoke with `--json`, parse stdout as JSON, assert `schema_version == "0.1"` (read the constant, don't hardcode) and assert on the field names you've committed to as public API.
- **No network.** If the command touches JWKS, use the offline fixtures in `tests/conftest.py` / `tests/helpers.py`. Network in tests fails CI under `filterwarnings = error` and is forbidden per `CLAUDE.md`.

Tests run in parallel (`-n auto`). No shared mutable state, no `os.chdir`, no env-var leaks — use `tmp_path` and `monkeypatch`.

## Step 5 — Verify

Tight inner loop while iterating on the new command's tests:

```sh
make fmt
uv run pytest -n auto tests/test_cmd_<snake_name>.py
```

Then **invoke `/check` for the full gate** before handing off — it runs lint + typecheck + tests + bandit + pip-audit consistently with CI, and that's what the project gates on. If coverage on the new module is below 80%, add tests; do not exclude the file from coverage reporting.

After `/check` is green, **run `/security-review`** — the new command touches public-API surfaces (a new `--json` schema, new help-text voice, a new entry in `CLI_HELP`) and the review catches voice drift and secret-leakage in error messages that the gate doesn't.

## Step 6 — Do not

- Do not bump the version. Releases are a separate `/release` workflow.
- Do not edit `CHANGELOG.md` (if present) unless the user asks — that often happens during release.
- Do not add `# type: ignore`, `# noqa`, or `# nosec` to make checks pass. If you're tempted, you're working around a real issue.
- Do not add the command to README.md without user confirmation — the README has its own structure and tone.
