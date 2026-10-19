import json
import time
from pathlib import Path
from typing import NoReturn

import click
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from jwt_toolkit.cli.algorithms import ensure_signing_algorithm, is_hmac
from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.credentials import SecretInputError, resolve_secret, secret_file_option
from jwt_toolkit.cli.decoding import (
    JSON_SCHEMA_VERSION,
    emit_error,
    resolve_token,
    safe_decode,
)
from jwt_toolkit.core.claims import (
    Check,
    check_audience,
    check_critical_headers,
    check_issuer,
    check_time_claims,
)
from jwt_toolkit.core.crypto import verify_asymmetric, verify_signature
from jwt_toolkit.core.errors import UnsupportedAlgorithmError
from jwt_toolkit.core.jwks import resolve_jwks_key

# Verify command — checks the signature and validates claims (exp, nbf, iat, iss, aud).
# Three key-source modes, mutually exclusive:
#   --secret      HMAC secret (HS* tokens), or --secret-file to read it from a file
#   --public-key  PEM public key (RS*/PS*/ES*/Ed* tokens)
#   --jwks-url    JWKS endpoint or file:// path; key resolved by the token's kid

RESULT_COLORS = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "WARN": "yellow",
}


@click.command(help="Verify a JWT's signature and standard claims (exp, nbf, iat, iss, aud).")
@click.argument("token")
@click.option(
    "--secret",
    default=None,
    help="HMAC secret to verify against (HS256/HS384/HS512). Mutually exclusive with --public-key.",
)
@secret_file_option
@click.option(
    "--public-key",
    "public_key_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help=(
        "Path to a PEM public key or X.509 certificate (RS*/PS*/ES*/Ed*). "
        "Mutually exclusive with --secret."
    ),
)
@click.option(
    "--jwks-url",
    "jwks_url",
    default=None,
    help=(
        "JWKS endpoint (https://, http://, or file://). The token's kid header "
        "selects the verification key. Mutually exclusive with --secret/--public-key."
    ),
)
@click.option("--issuer", default=None, help="Expected issuer (iss claim)")
@click.option("--audience", default=None, help="Expected audience (aud claim)")
@click.option(
    "--leeway",
    default=0,
    show_default=True,
    type=click.IntRange(0),
    help="Clock-skew tolerance in seconds for exp/nbf checks",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a machine-readable JSON report.",
)
def verify(
    token: str,
    *,
    secret: str | None,
    secret_path: Path | None,
    public_key_path: Path | None,
    jwks_url: str | None,
    issuer: str | None,
    audience: str | None,
    leeway: int,
    as_json: bool,
):
    try:
        secret = resolve_secret(secret, secret_path)
    except SecretInputError as exc:
        emit_error(
            code="invalid_key_options",
            title="Invalid Input",
            headline=exc.headline,
            details=exc.details,
            as_json=as_json,
        )
        raise SystemExit(2) from exc

    token = resolve_token(token, as_json=as_json)

    decoded = safe_decode(token, as_json=as_json)
    try:
        alg = ensure_signing_algorithm(decoded.header)
    except UnsupportedAlgorithmError as exc:
        emit_error(
            code="unsupported_algorithm",
            title=exc.title,
            headline=exc.headline,
            details=exc.details,
            as_json=as_json,
        )
        raise SystemExit(2) from exc

    _validate_key_inputs(
        alg,
        secret=secret,
        public_key_path=public_key_path,
        jwks_url=jwks_url,
        as_json=as_json,
    )

    try:
        sig_valid = _verify_signature(
            decoded,
            alg,
            secret=secret,
            public_key_path=public_key_path,
            jwks_url=jwks_url,
        )
    except ValueError as exc:
        emit_error(
            code="key_error",
            title="Key Error",
            headline="Could not verify signature with the provided key",
            details=(str(exc),),
            as_json=as_json,
        )
        raise SystemExit(2) from exc

    checks = [
        Check("PASS", "signature", "Signature is valid")
        if sig_valid
        else Check("FAIL", "signature", "Signature is invalid, wrong key or tampered token"),
        *check_critical_headers(decoded.header),
        *check_time_claims(decoded.payload, now=time.time(), leeway=leeway),
    ]
    if issuer is not None:
        checks.append(check_issuer(decoded.payload, issuer))
    if audience is not None:
        checks.append(check_audience(decoded.payload, audience))
    failed = any(c.result == "FAIL" for c in checks)

    if as_json:
        _emit_json(checks, failed=failed)
    else:
        _render_results(checks, failed=failed)


def _validate_key_inputs(
    alg: str,
    *,
    secret: str | None,
    public_key_path: Path | None,
    jwks_url: str | None,
    as_json: bool,
) -> None:
    def reject(headline: str, *details: str) -> NoReturn:
        emit_error(
            code="invalid_key_options",
            title="Invalid Input",
            headline=headline,
            details=details,
            as_json=as_json,
        )
        raise SystemExit(2)

    # Enforce exactly-one key source. Counting truthy options is clearer than
    # nested pairwise checks once a third mode enters the picture.
    sources = sum(x is not None for x in (secret, public_key_path, jwks_url))
    if sources > 1:
        reject("Pass only one of --secret, --public-key, or --jwks-url")

    if is_hmac(alg):
        if jwks_url is not None or public_key_path is not None:
            reject(f"{alg} is an HMAC algorithm — use --secret")
        if not secret:
            reject(
                f"{alg} requires --secret or --secret-file",
                "Provide the HMAC secret the token was signed with.",
            )
        return

    # Asymmetric path — accept either a PEM file or a JWKS URL.
    if public_key_path is None and jwks_url is None:
        reject(
            f"{alg} requires --public-key or --jwks-url",
            "Provide a PEM-encoded public key, or a JWKS endpoint the token's kid resolves against.",
        )
    if secret is not None:
        reject(f"{alg} is an asymmetric algorithm — use --public-key or --jwks-url, not --secret")


def _verify_signature(
    decoded,
    alg: str,
    *,
    secret: str | None,
    public_key_path: Path | None,
    jwks_url: str | None,
) -> bool:
    if is_hmac(alg):
        return verify_signature(
            decoded.header_b64, decoded.payload_b64, decoded.signature, secret or "", alg
        )
    if jwks_url is not None:
        kid = decoded.header.get("kid")
        pem_bytes = resolve_jwks_key(jwks_url, kid=kid, alg=alg)
    else:
        pem_bytes = public_key_path.read_bytes()  # type: ignore[union-attr]
    return verify_asymmetric(
        decoded.header_b64, decoded.payload_b64, decoded.signature, pem_bytes, alg
    )


def _emit_json(checks: list[Check], *, failed: bool) -> None:
    document = {
        "schema_version": JSON_SCHEMA_VERSION,
        "valid": not failed,
        "checks": [{"result": c.result, "check": c.check, "detail": c.detail} for c in checks],
    }
    click.echo(json.dumps(document, indent=2))
    raise SystemExit(1 if failed else 0)


def _render_results(checks: list[Check], *, failed: bool) -> None:
    table = Table(title="Verification Checks", show_lines=True)
    table.add_column("Result", style="bold", width=8)
    table.add_column("Check", width=12)
    table.add_column("Detail")

    for c in checks:
        color = RESULT_COLORS[c.result]
        table.add_row(f"[{color}]{c.result}[/{color}]", escape(c.check), escape(c.detail))

    console.print(table)

    if failed:
        console.print(Panel("[bold red]INVALID[/bold red]", border_style="red"))
        raise SystemExit(1)
    console.print(Panel("[bold green]VALID[/bold green]", border_style="green"))
