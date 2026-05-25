import json

import click
from rich.panel import Panel
from rich.syntax import Syntax

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, resolve_token, safe_decode

# Decode command — pretty-print the header and payload of a JWT without audit noise.


@click.command(help="Decode a JWT and pretty-print its header and payload.")
@click.argument("token")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON output.")
def decode(token: str, as_json: bool):
    token = resolve_token(token)
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
    console.print(
        Panel(
            decoded.signature or "[dim](none)[/dim]",
            title="Signature",
            border_style="dim",
        )
    )
