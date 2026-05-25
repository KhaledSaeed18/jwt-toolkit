import time

import click
from rich.panel import Panel
from rich.table import Table

from jwt_toolkit.cli.algorithms import ensure_hmac_algorithm
from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import render_algorithm_error, safe_decode
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.crypto import verify_signature
from jwt_toolkit.core.errors import UnsupportedAlgorithmError

# Verify command — checks the signature and validates claims (exp, nbf, iss, aud).

RESULT_COLORS = {
    "PASS": "bold green",
    "FAIL": "bold red",
    "WARN": "yellow",
}


@click.command()
@click.argument("token")
@click.option("--secret", required=True, help="The HMAC secret to verify against")
@click.option("--issuer", default=None, help="Expected issuer (iss claim)")
@click.option("--audience", default=None, help="Expected audience (aud claim)")
def verify(token: str, secret: str, issuer: str | None, audience: str | None):
    if not secret:
        print_error(
            "Secret cannot be empty",
            "Provide the HMAC secret the token was signed with",
            title="Invalid Input",
        )
        raise SystemExit(2)

    decoded = safe_decode(token)
    try:
        alg = ensure_hmac_algorithm(decoded.header, action="verify")
    except UnsupportedAlgorithmError as exc:
        render_algorithm_error(exc)
        raise SystemExit(2) from exc

    rows: list[tuple[str, str, str]] = []
    failed = False

    sig_valid = verify_signature(
        decoded.header_b64, decoded.payload_b64, decoded.signature, secret, alg
    )
    if sig_valid:
        rows.append(("PASS", "signature", "Signature is valid"))
    else:
        rows.append(("FAIL", "signature", "Signature is invalid, wrong secret or tampered token"))
        failed = True

    failed |= _check_temporal_claims(decoded.payload, rows)
    if issuer is not None:
        failed |= _check_issuer(decoded.payload, issuer, rows)
    if audience is not None:
        failed |= _check_audience(decoded.payload, audience, rows)

    _render_results(rows, failed=failed)


def _check_temporal_claims(payload: dict, rows: list[tuple[str, str, str]]) -> bool:
    now = time.time()
    failed = False

    exp = payload.get("exp")
    if exp is None:
        rows.append(("WARN", "exp", "No expiry claim"))
    elif not isinstance(exp, (int, float)):
        rows.append(("FAIL", "exp", f"exp is not a number: {exp!r}"))
        failed = True
    elif exp < now:
        rows.append(("FAIL", "exp", "Token is expired"))
        failed = True
    else:
        rows.append(("PASS", "exp", "Token is not expired"))

    nbf = payload.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)):
            rows.append(("FAIL", "nbf", f"nbf is not a number: {nbf!r}"))
            failed = True
        elif nbf > now:
            rows.append(("FAIL", "nbf", "Token is not yet valid (nbf is in the future)"))
            failed = True

    return failed


def _check_issuer(payload: dict, issuer: str, rows: list[tuple[str, str, str]]) -> bool:
    if payload.get("iss") == issuer:
        rows.append(("PASS", "iss", f"Issuer matches '{issuer}'"))
        return False
    rows.append(("FAIL", "iss", f"Issuer mismatch: expected '{issuer}', got '{payload.get('iss')}'"))
    return True


def _check_audience(payload: dict, audience: str, rows: list[tuple[str, str, str]]) -> bool:
    # aud can be a string or a list per RFC 7519.
    aud = payload.get("aud")
    aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if audience in aud_list:
        rows.append(("PASS", "aud", f"Audience matches '{audience}'"))
        return False
    rows.append(("FAIL", "aud", f"Audience mismatch: expected '{audience}', got {aud!r}"))
    return True


def _render_results(rows: list[tuple[str, str, str]], *, failed: bool) -> None:
    table = Table(title="Verification Checks", show_lines=True)
    table.add_column("Result", style="bold", width=8)
    table.add_column("Check", width=12)
    table.add_column("Detail")

    for result, check, detail in rows:
        color = RESULT_COLORS[result]
        table.add_row(f"[{color}]{result}[/{color}]", check, detail)

    console.print(table)

    if failed:
        console.print(Panel("[bold red]INVALID[/bold red]", border_style="red"))
        # Exit 1 so CI/scripts can gate on the verification outcome.
        raise SystemExit(1)
    console.print(Panel("[bold green]VALID[/bold green]", border_style="green"))
