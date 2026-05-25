import json

import click

from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS
from jwt_toolkit.core.crypto import sign as _sign
from jwt_toolkit.core.encoding import base64url_encode

# Sign command — construct and mint a JWT from a header+payload+secret.


@click.command(help="Mint a new JWT signed with an HMAC secret.")
@click.option("--payload", "payload_json", required=True, help="JWT payload as a JSON string")
@click.option("--secret", required=True, help="HMAC secret to sign with")
@click.option(
    "--alg",
    default="HS256",
    show_default=True,
    type=click.Choice(list(SUPPORTED_ALGORITHMS.keys()), case_sensitive=False),
    help="Signing algorithm (ignored if --header overrides 'alg')",
)
@click.option(
    "--header",
    "header_json",
    default=None,
    help='Override the JWT header as a JSON string. Default: {"alg":"<alg>","typ":"JWT"}',
)
def sign(payload_json: str, secret: str, alg: str, header_json: str | None):
    if not secret:
        print_error(
            "Secret cannot be empty",
            "Provide the HMAC secret to sign with",
            title="Invalid Input",
        )
        raise SystemExit(2)

    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        print_error(
            "Invalid payload JSON",
            f"JSON error: {exc.msg}",
            'Provide a valid JSON object, e.g. \'{"sub": "1", "exp": 9999999999}\'',
            title="Invalid Input",
        )
        raise SystemExit(2) from exc

    if header_json is None:
        header = {"alg": alg.upper(), "typ": "JWT"}
    else:
        try:
            header = json.loads(header_json)
        except json.JSONDecodeError as exc:
            print_error(
                "Invalid header JSON",
                f"JSON error: {exc.msg}",
                title="Invalid Input",
            )
            raise SystemExit(2) from exc

    sign_alg = str(header.get("alg", alg)).upper()
    if sign_alg not in SUPPORTED_ALGORITHMS:
        print_error(
            f"Unsupported algorithm: {sign_alg}",
            f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}",
            "Use HS256, HS384, or HS512",
            title="Algorithm Error",
        )
        raise SystemExit(2)

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _sign(header_b64, payload_b64, secret, sign_alg)

    token = f"{header_b64}.{payload_b64}.{signature}"
    click.echo(token)
