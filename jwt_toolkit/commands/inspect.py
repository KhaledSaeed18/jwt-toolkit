import click
import json
from jwt_toolkit.core.decoder import decode_token

@click.command()
@click.argument("token")
def inspect(token: str):
    try:
        header, payload, signature = decode_token(token)

        click.echo("\nHeader: ")
        click.echo(json.dumps(header, indent=2))

        if str(header.get("alg", "")).lower() == "none":
            click.echo(click.style("Warning: alg is none, token is unsigned", fg="red"))

        click.echo("\nPayload: ")
        click.echo(json.dumps(payload, indent=2))

        click.echo("\nSignature: ")
        click.echo(signature if signature else "(none)")

    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
