import binascii
import json
import time
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from jwt_toolkit.core.decoder import decode_token, split_token
from jwt_toolkit.core.crypto import verify_signature, SUPPORTED_ALGORITHMS

console = Console()

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
    try:
        header, payload, signature = decode_token(token)
        header_b64, payload_b64, _ = split_token(token)

        alg = header.get("alg", "").upper()

        if alg == "NONE":
            console.print(Panel(
                "[bold red]Token uses alg: none, it has no signature to verify[/bold red]\n\n"
                "[dim]This token is completely unsigned and trivially forgeable[/dim]",
                title="Verification Error",
                border_style="red"
            ))
            raise SystemExit(2)

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

        sig_valid = verify_signature(header_b64, payload_b64, signature, secret, alg)
        if sig_valid:
            rows.append(("PASS", "signature", "Signature is valid"))
        else:
            rows.append(("FAIL", "signature", "Signature is invalid, wrong secret or tampered token"))
            failed = True

        now = time.time()
        exp = payload.get("exp")
        if exp is None:
            rows.append(("WARN", "exp", "No expiry claim"))
        elif exp < now:
            rows.append(("FAIL", "exp", "Token is expired"))
            failed = True
        else:
            rows.append(("PASS", "exp", "Token is not expired"))

        nbf = payload.get("nbf")
        if nbf is not None and nbf > now:
            rows.append(("FAIL", "nbf", "Token is not yet valid (nbf is in the future)"))
            failed = True

        if issuer is not None:
            if payload.get("iss") == issuer:
                rows.append(("PASS", "iss", f"Issuer matches '{issuer}'"))
            else:
                rows.append(("FAIL", "iss", f"Issuer mismatch: expected '{issuer}', got '{payload.get('iss')}'"))
                failed = True

        if audience is not None:
            if payload.get("aud") == audience:
                rows.append(("PASS", "aud", f"Audience matches '{audience}'"))
            else:
                rows.append(("FAIL", "aud", f"Audience mismatch: expected '{audience}', got '{payload.get('aud')}'"))
                failed = True

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
        else:
            console.print(Panel("[bold green]VALID[/bold green]", border_style="green"))

    except binascii.Error:
        console.print(Panel(
            "[bold red]Token contains invalid base64url encoding[/bold red]\n\n"
            "[dim]One or more parts could not be decoded[/dim]\n"
            "[dim]The token may be truncated or corrupted[/dim]",
            title="Decode Error",
            border_style="red"
        ))
        raise SystemExit(2)

    except json.JSONDecodeError as e:
        console.print(Panel(
            "[bold red]Token decoded but header or payload is not valid JSON[/bold red]\n\n"
            f"[dim]JSON error : {e.msg}[/dim]\n"
            "[dim]The token structure may be corrupted[/dim]",
            title="Parse Error",
            border_style="red"
        ))
        raise SystemExit(2)

    except ValueError as e:
        console.print(Panel(
            f"[bold red]{e}[/bold red]\n\n"
            "[dim]A JWT must have exactly 3 base64url parts separated by dots[/dim]\n"
            "[dim]Format : <header>.<payload>.<signature>[/dim]",
            title="Invalid Token",
            border_style="red"
        ))
        raise SystemExit(2)
