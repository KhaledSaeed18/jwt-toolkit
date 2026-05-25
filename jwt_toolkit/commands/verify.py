import binascii
import json
import time
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from jwt_toolkit.core.decoder import decode_token, split_token
from jwt_toolkit.core.crypto import verify_signature, SUPPORTED_ALGORITHMS

# Verify command — checks the signature and validates claims (exp, nbf, iss, aud).

console = Console()

# Map result status to display colors.
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
    # Verify a JWT signature and validate its claims.
    try:
        if not secret:
            console.print(Panel(
                "[bold red]Secret cannot be empty[/bold red]\n\n"
                "[dim]Provide the HMAC secret the token was signed with[/dim]",
                title="Invalid Input",
                border_style="red"
            ))
            raise SystemExit(2)

        # Decode the token and extract its parts for signature verification.
        header, payload, signature = decode_token(token)
        header_b64, payload_b64, _ = split_token(token)
        alg = header.get("alg", "").upper()

        # alg: none means the token is unsigned — nothing to verify.
        if alg == "NONE":
            console.print(Panel(
                "[bold red]Token uses alg: none, it has no signature to verify[/bold red]\n\n"
                "[dim]This token is completely unsigned and trivially forgeable[/dim]",
                title="Verification Error",
                border_style="red"
            ))
            raise SystemExit(2)

        # Reject algorithms we don't support (e.g. RS256, asymmetric keys).
        if alg not in SUPPORTED_ALGORITHMS:
            console.print(Panel(
                f"[bold red]Unsupported algorithm: {alg}[/bold red]\n\n"
                f"[dim]Supported : {', '.join(SUPPORTED_ALGORITHMS)}[/dim]",
                title="Verification Error",
                border_style="red"
            ))
            raise SystemExit(2)

        rows = []
        failed = False

        # Verify the HMAC signature.
        sig_valid = verify_signature(header_b64, payload_b64, signature, secret, alg)
        if sig_valid:
            rows.append(("PASS", "signature", "Signature is valid"))
        else:
            rows.append(("FAIL", "signature", "Signature is invalid, wrong secret or tampered token"))
            failed = True

        # Check expiry.
        now = time.time()
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

        # Check not-before claim.
        nbf = payload.get("nbf")
        if nbf is not None:
            if not isinstance(nbf, (int, float)):
                rows.append(("FAIL", "nbf", f"nbf is not a number: {nbf!r}"))
                failed = True
            elif nbf > now:
                rows.append(("FAIL", "nbf", "Token is not yet valid (nbf is in the future)"))
                failed = True

        # Check issuer if provided.
        if issuer is not None:
            if payload.get("iss") == issuer:
                rows.append(("PASS", "iss", f"Issuer matches '{issuer}'"))
            else:
                rows.append(("FAIL", "iss", f"Issuer mismatch: expected '{issuer}', got '{payload.get('iss')}'"))
                failed = True

        # Check audience if provided. aud can be a string or a list per RFC 7519.
        if audience is not None:
            aud = payload.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
            if audience in aud_list:
                rows.append(("PASS", "aud", f"Audience matches '{audience}'"))
            else:
                rows.append(("FAIL", "aud", f"Audience mismatch: expected '{audience}', got {aud!r}"))
                failed = True

        # Display verification results.
        table = Table(title="Verification Checks", show_lines=True)
        table.add_column("Result", style="bold", width=8)
        table.add_column("Check", width=12)
        table.add_column("Detail")

        for result, check, detail in rows:
            color = RESULT_COLORS[result]
            table.add_row(f"[{color}]{result}[/{color}]", check, detail)

        console.print(table)

        # Overall verdict.
        if failed:
            console.print(Panel("[bold red]INVALID[/bold red]", border_style="red"))
        else:
            console.print(Panel("[bold green]VALID[/bold green]", border_style="green"))

    except binascii.Error:
        # Token parts could not be base64url-decoded.
        console.print(Panel(
            "[bold red]Token contains invalid base64url encoding[/bold red]\n\n"
            "[dim]One or more parts could not be decoded[/dim]\n"
            "[dim]The token may be truncated or corrupted[/dim]",
            title="Decode Error",
            border_style="red"
        ))
        raise SystemExit(2)

    except json.JSONDecodeError as e:
        # Base64 decoded fine but the content is not valid JSON.
        console.print(Panel(
            "[bold red]Token decoded but header or payload is not valid JSON[/bold red]\n\n"
            f"[dim]JSON error : {e.msg}[/dim]\n"
            "[dim]The token structure may be corrupted[/dim]",
            title="Parse Error",
            border_style="red"
        ))
        raise SystemExit(2)

    except ValueError as e:
        # Token does not have the expected 3-part structure.
        console.print(Panel(
            f"[bold red]{e}[/bold red]\n\n"
            "[dim]A JWT must have exactly 3 base64url parts separated by dots[/dim]\n"
            "[dim]Format : <header>.<payload>.<signature>[/dim]",
            title="Invalid Token",
            border_style="red"
        ))
        raise SystemExit(2)
