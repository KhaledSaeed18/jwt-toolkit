import json
from pathlib import Path

import click

from jwt_toolkit.cli.algorithms import is_asymmetric, is_hmac
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.crypto import (
    ALL_SIGNING_ALGORITHMS,
)
from jwt_toolkit.core.crypto import (
    sign as _sign_hmac,
)
from jwt_toolkit.core.crypto import (
    sign_asymmetric as _sign_asymmetric,
)
from jwt_toolkit.core.encoding import base64url_encode

# Sign command — construct and mint a JWT from a header+payload and either an
# HMAC secret or a PEM-encoded private key.

_ALG_CHOICES = sorted(ALL_SIGNING_ALGORITHMS)


@click.command(help="Mint a new JWT signed with an HMAC secret or an asymmetric private key.")
@click.option("--payload", "payload_json", required=True, help="JWT payload as a JSON string")
@click.option(
    "--secret",
    default=None,
    help="HMAC secret (HS256/HS384/HS512). Mutually exclusive with --private-key.",
)
@click.option(
    "--private-key",
    "private_key_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Path to a PEM-encoded private key (RS*/PS*/ES*). Mutually exclusive with --secret.",
)
@click.option(
    "--alg",
    default="HS256",
    show_default=True,
    type=click.Choice(_ALG_CHOICES, case_sensitive=False),
    help="Signing algorithm (ignored if --header overrides 'alg').",
)
@click.option(
    "--header",
    "header_json",
    default=None,
    help='Override the JWT header as a JSON string. Default: {"alg":"<alg>","typ":"JWT"}',
)
def sign(
    payload_json: str,
    secret: str | None,
    private_key_path: Path | None,
    alg: str,
    header_json: str | None,
):
    payload = _parse_json_arg(payload_json, label="payload")
    header = (
        {"alg": alg.upper(), "typ": "JWT"}
        if header_json is None
        else _parse_json_arg(header_json, label="header")
    )

    sign_alg = str(header.get("alg", alg)).upper()
    if sign_alg not in ALL_SIGNING_ALGORITHMS:
        print_error(
            f"Unsupported algorithm: {sign_alg}",
            f"Supported: {', '.join(_ALG_CHOICES)}",
            title="Algorithm Error",
        )
        raise SystemExit(2)

    _validate_key_inputs(sign_alg, secret=secret, private_key_path=private_key_path)

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if is_hmac(sign_alg):
        signature = _sign_hmac(header_b64, payload_b64, secret or "", sign_alg)
    else:
        try:
            pem_bytes = private_key_path.read_bytes()  # type: ignore[union-attr]
            signature = _sign_asymmetric(header_b64, payload_b64, pem_bytes, sign_alg)
        except ValueError as exc:
            print_error(
                "Could not sign with the provided private key",
                str(exc),
                title="Key Error",
            )
            raise SystemExit(2) from exc

    click.echo(f"{header_b64}.{payload_b64}.{signature}")


def _parse_json_arg(raw: str, *, label: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        print_error(
            f"Invalid {label} JSON",
            f"JSON error: {exc.msg}",
            title="Invalid Input",
        )
        raise SystemExit(2) from exc


def _validate_key_inputs(alg: str, *, secret: str | None, private_key_path: Path | None) -> None:
    if secret is not None and private_key_path is not None:
        print_error(
            "Pass either --secret or --private-key, not both",
            title="Invalid Input",
        )
        raise SystemExit(2)

    if is_hmac(alg):
        if not secret:
            print_error(
                f"{alg} requires --secret",
                "Provide the HMAC secret to sign with.",
                title="Invalid Input",
            )
            raise SystemExit(2)
        if private_key_path is not None:
            print_error(
                f"{alg} is an HMAC algorithm — use --secret, not --private-key",
                title="Invalid Input",
            )
            raise SystemExit(2)
        return

    if is_asymmetric(alg):
        if private_key_path is None:
            print_error(
                f"{alg} requires --private-key",
                "Provide a PEM-encoded private key (PKCS#8 or traditional).",
                title="Invalid Input",
            )
            raise SystemExit(2)
        if secret is not None:
            print_error(
                f"{alg} is an asymmetric algorithm — use --private-key, not --secret",
                title="Invalid Input",
            )
            raise SystemExit(2)
