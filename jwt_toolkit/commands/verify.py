import json
import time
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.credentials import resolve_secret, secret_file_option
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, resolve_token, safe_decode
from jwt_toolkit.cli.errors import ToolkitCommand, reported_as
from jwt_toolkit.core.claims import Check
from jwt_toolkit.core.errors import JwtToolkitError
from jwt_toolkit.core.jwks import resolve_jwks_public_key
from jwt_toolkit.core.keys import HmacKey, VerificationKey, load_public_key_for
from jwt_toolkit.core.verifier import Expectations, KeyResolver, verify_token

RESULT_COLORS = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "WARN": "yellow",
}


@click.command(
    cls=ToolkitCommand,
    help="Verify a JWT's signature and standard claims (exp, nbf, iat, iss, aud).",
)
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
) -> None:
    secret = resolve_secret(secret, secret_path)
    decoded = safe_decode(resolve_token(token))
    _require_one_key_source(secret=secret, public_key_path=public_key_path, jwks_url=jwks_url)

    key = _verification_key(secret=secret, public_key_path=public_key_path, jwks_url=jwks_url)
    try:
        result = verify_token(
            decoded,
            key=key,
            now=time.time(),
            expected=Expectations(issuer=issuer, audience=audience, leeway=leeway),
            key_checks=_transport_checks(jwks_url),
        )
    except JwtToolkitError as exc:
        raise reported_as(
            exc,
            code="key_error",
            title="Key Error",
            headline="Could not verify signature with the provided key",
        ) from exc
    checks = list(result.checks)
    failed = not result.valid

    if as_json:
        _emit_json(checks, failed=failed)
    else:
        _render_results(checks, failed=failed)


def _require_one_key_source(
    *,
    secret: str | None,
    public_key_path: Path | None,
    jwks_url: str | None,
) -> None:
    # Which key the operator supplied is a usage question (exit 2); whether the
    # token fits that key is a verdict on the token (exit 1).
    sources = sum(x is not None for x in (secret, public_key_path, jwks_url))
    if sources == 1 and secret != "":
        return
    headline = (
        "Pass only one of --secret, --public-key, or --jwks-url"
        if sources > 1
        else "Provide the key to verify with"
    )
    raise JwtToolkitError(
        headline=headline,
        details=(
            "--secret or --secret-file for HS* tokens; --public-key or --jwks-url for "
            "RS*, PS*, ES*, and Ed* tokens.",
        ),
        code="invalid_key_options",
        title="Invalid Input",
    )


def _verification_key(
    *, secret: str | None, public_key_path: Path | None, jwks_url: str | None
) -> VerificationKey | KeyResolver:
    # Keys are loaded only once the token's algorithm has been accepted, so a token
    # rejected on its own merits is a verdict (exit 1), never a key error.
    if secret is not None:
        return HmacKey.from_text(secret)
    if jwks_url is not None:
        url = jwks_url
        return lambda decoded, spec: resolve_jwks_public_key(
            url, kid=decoded.header.get("kid"), alg=spec.name
        )
    path = public_key_path
    assert path is not None  # _require_one_key_source guarantees one source
    return lambda _decoded, spec: load_public_key_for(path.read_bytes(), spec)


def _transport_checks(jwks_url: str | None) -> list[Check]:
    # Plain HTTP stays allowed for compatibility, but the verdict must say the
    # key itself was exposed to tampering in transit.
    if jwks_url is None or urlparse(jwks_url).scheme != "http":
        return []
    return [
        Check(
            "WARN",
            "jwks",
            "Keys were fetched over plain HTTP, so anyone on the network path could "
            "substitute them; use an https:// JWKS URL",
        )
    ]


def _emit_json(checks: list[Check], *, failed: bool) -> None:
    document = {
        "schema_version": JSON_SCHEMA_VERSION,
        "valid": not failed,
        "checks": [{"result": c.result, "check": c.check, "detail": c.detail} for c in checks],
    }
    click.echo(json.dumps(document, indent=2))
    raise click.exceptions.Exit(1 if failed else 0)


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
        raise click.exceptions.Exit(1)
    console.print(Panel("[bold green]VALID[/bold green]", border_style="green"))
