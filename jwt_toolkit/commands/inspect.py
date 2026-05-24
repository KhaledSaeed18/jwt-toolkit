import click
import json
from jwt_toolkit.core.decoder import decode_token

# Command to inspect a JWT token and display its header, payload, and signature.

@click.command()
@click.argument("token")
def inspect(token: str):
    try:
        # Decode the token and extract its components.
        header, payload, signature = decode_token(token)

        # Display the decoded components.
        click.echo("\nHeader: ")
        # Display the header in a pretty-printed JSON format.
        click.echo(json.dumps(header, indent=2))

        # Check if the token is unsigned (alg is none) and display a warning if so.
        if str(header.get("alg", "")).lower() == "none":
            click.echo(click.style("Warning: alg is none, token is unsigned", fg="red"))

        # Display the payload and signature.
        click.echo("\nPayload: ")
        click.echo(json.dumps(payload, indent=2))

        # Display the signature if it exists. If the signature is empty, indicate that the token is unsigned.
        click.echo("\nSignature: ")
        click.echo(signature if signature else "(none)")

    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
