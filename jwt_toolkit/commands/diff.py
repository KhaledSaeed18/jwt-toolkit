import json

import click
from rich.table import Table
from rich.text import Text

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, emit_error, resolve_token
from jwt_toolkit.cli.panels import print_success
from jwt_toolkit.core.decoder import DecodedToken, decode_token
from jwt_toolkit.core.diff import FieldChange, TokenDiff, diff_tokens
from jwt_toolkit.core.errors import TokenDecodeError

_UNVERIFIED_NOTE = "Neither token was verified. This compares contents only."


@click.command(help="Compare two JWTs and show which header and claim fields changed.")
@click.argument("before")
@click.argument("after")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON output.")
@click.option(
    "--exit-code",
    "exit_code",
    is_flag=True,
    help="Exit with status 1 when the tokens differ, for use in scripts.",
)
@click.pass_context
def diff(ctx: click.Context, before: str, after: str, as_json: bool, exit_code: bool):
    if before == "-" and after == "-":
        emit_error(
            code="stdin_conflict",
            title="Input Error",
            headline="Only one token can be read from stdin",
            details=("Pass the other token directly or as @path",),
            as_json=as_json,
        )
        raise SystemExit(2)

    result = diff_tokens(
        _decode("before", before, as_json=as_json),
        _decode("after", after, as_json=as_json),
    )

    if as_json:
        click.echo(json.dumps(_json_document(result), indent=2))
    else:
        _render(result)

    if exit_code and not result.identical:
        ctx.exit(1)


def _decode(side: str, raw: str, *, as_json: bool) -> DecodedToken:
    token = resolve_token(raw, as_json=as_json)
    try:
        return decode_token(token)
    except TokenDecodeError as exc:
        emit_error(
            code=exc.code,
            title=exc.title,
            headline=f"{side.capitalize()} token: {exc.headline}",
            details=exc.details,
            as_json=as_json,
            extra={"input": side},
        )
        raise SystemExit(2) from exc


def _json_document(result: TokenDiff) -> dict:
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "verified": False,
        "identical": result.identical,
        "signature_changed": result.signature_changed,
        "header_encoding_changed": result.header_encoding_changed,
        "payload_encoding_changed": result.payload_encoding_changed,
        "changes": [_json_change(change) for change in result.changes],
    }


def _json_change(change: FieldChange) -> dict:
    entry: dict = {
        "section": change.section,
        "path": change.path,
        "change": change.kind,
        "notable": change.notable,
    }
    if change.kind != "added":
        entry["before"] = change.before
    if change.kind != "removed":
        entry["after"] = change.after
    return entry


def _render(result: TokenDiff) -> None:
    if result.identical:
        print_success("Tokens are identical", _UNVERIFIED_NOTE, title="Token Diff")
        return

    if result.changes:
        console.print(_changes_table(result.changes))

    notable = sum(change.notable for change in result.changes)
    lines = [
        f"Field changes : {len(result.changes)} ({notable} notable)",
        f"Signature     : {'changed' if result.signature_changed else 'unchanged'}",
    ]
    for section, changed in (
        ("Header", result.header_encoding_changed),
        ("Payload", result.payload_encoding_changed),
    ):
        if changed:
            lines.append(
                f"{section} JSON is the same but encoded differently (key order or spacing)"
            )
    lines.append(_UNVERIFIED_NOTE)
    print_success(
        "Tokens differ",
        *lines,
        title="Token Diff",
        headline_style="bold yellow",
        border_style="yellow",
    )


def _changes_table(changes: tuple[FieldChange, ...]) -> Table:
    table = Table(title="Changed Fields", show_lines=True)
    table.add_column("", width=1, style="bold yellow")
    table.add_column("Section", style="dim")
    table.add_column("Path", style="bold", overflow="fold")
    table.add_column("Change")
    table.add_column("Before", overflow="fold")
    table.add_column("After", overflow="fold")
    for change in changes:
        table.add_row(
            "!" if change.notable else "",
            change.section,
            Text(change.path),
            change.kind,
            _cell(change.before, present=change.kind != "added"),
            _cell(change.after, present=change.kind != "removed"),
        )
    return table


def _cell(value: object, *, present: bool) -> Text:
    if not present:
        return Text("(absent)", style="dim")
    # Text keeps token-supplied strings from being parsed as Rich markup.
    return Text(json.dumps(value, ensure_ascii=False))
