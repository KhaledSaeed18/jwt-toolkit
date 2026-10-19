import json
import time

import click
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, resolve_token, safe_decode
from jwt_toolkit.core.encoding import JsonObject
from jwt_toolkit.core.timestamps import describe_time_claims


@click.command(help="Decode a JWT and pretty-print its header and payload.")
@click.argument("token")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON output.")
def decode(token: str, as_json: bool) -> None:
    token = resolve_token(token, as_json=as_json)
    decoded = safe_decode(token, as_json=as_json)

    if as_json:
        click.echo(
            json.dumps(
                {
                    "schema_version": JSON_SCHEMA_VERSION,
                    "header": decoded.header,
                    "payload": decoded.payload,
                    "signature": decoded.signature,
                },
                indent=2,
            )
        )
        return

    console.print(
        Panel(
            Syntax(json.dumps(decoded.header, indent=2), "json", theme="monokai"),
            title="Header",
            border_style="blue",
        )
    )
    console.print(
        Panel(
            Syntax(json.dumps(decoded.payload, indent=2), "json", theme="monokai"),
            title="Payload",
            border_style="blue",
        )
    )
    times = _time_claims_table(decoded.payload)
    if times is not None:
        console.print(times)
    console.print(
        Panel(
            escape(decoded.signature) if decoded.signature else "[dim](none)[/dim]",
            title="Signature",
            border_style="dim",
        )
    )


def _time_claims_table(payload: JsonObject) -> Table | None:
    claims = describe_time_claims(payload, now=time.time())
    if not claims:
        return None
    table = Table(
        title="Time Claims",
        caption="Read from the token; not checked against a key or a clock policy.",
        caption_style="dim",
    )
    table.add_column("Claim", style="bold")
    table.add_column("Value")
    table.add_column("UTC")
    table.add_column("Relative")
    for claim in claims:
        value = Text(json.dumps(claim.value))
        if claim.problem is not None:
            table.add_row(claim.name, value, Text(claim.problem, style="yellow"), "")
        else:
            table.add_row(claim.name, value, claim.utc, claim.relative)
    return table
