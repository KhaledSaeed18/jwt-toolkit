import binascii
import json
import time
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from jwt_toolkit.core.decoder import decode_token, split_token
from jwt_toolkit.core.crypto import verify_signature, SUPPORTED_ALGORITHMS

# Command to verify a JWT token's signature and claims against a provided secret key, with options to check the issuer and audience claims. The command provides detailed feedback on the verification results, including any issues with the signature, expiration, not-before time, issuer, and audience claims.

console = Console()

# Define result statuses for verification checks, which can be used to categorize and display the results of the verification process in a user-friendly manner with appropriate color coding.
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
        # Decode the JWT token to extract its header, payload, and signature components for verification.
        header, payload, signature = decode_token(token) 
        # Split the token into its base64url-encoded header and payload components, which are needed for signature verification.
        header_b64, payload_b64, _ = split_token(token) 

        # Extract the "alg" field from the header to determine the signing algorithm used for the token, which is necessary for verifying the signature correctly.
        alg = header.get("alg", "").upper()

        # Check if the algorithm is "none", which indicates that the token is unsigned and therefore cannot be verified, and provide an appropriate error message to inform the user of this critical issue.
        if alg == "NONE":
            console.print(Panel(
                "[bold red]Token uses alg: none, it has no signature to verify[/bold red]\n\n"
                "[dim]This token is completely unsigned and trivially forgeable[/dim]",
                title="Verification Error",
                border_style="red"
            ))
            raise SystemExit(2)

        # Check if the algorithm is supported, and provide an appropriate error message if it is not. Unsupported algorithms may indicate that the token is using a weak or unrecognized signing method, which can lead to verification failures or security issues.
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

        # Verify the token's signature using the provided secret and the specified algorithm, and provide feedback on whether the signature is valid or invalid, which is a critical part of the verification process to ensure the integrity and authenticity of the token.
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

        # Check if the token is not yet valid (nbf is in the future), and provide feedback on the validity of the token based on the not-before claim, which is important for ensuring that the token is only accepted within its intended time frame.
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
        # Handle errors related to invalid base64url encoding, which can occur if the token is truncated, corrupted, or not properly formatted as a JWT.
        console.print(Panel(
            "[bold red]Token contains invalid base64url encoding[/bold red]\n\n"
            "[dim]One or more parts could not be decoded[/dim]\n"
            "[dim]The token may be truncated or corrupted[/dim]",
            title="Decode Error",
            border_style="red"
        ))
        raise SystemExit(2)

    except json.JSONDecodeError as e:
        # Handle errors related to invalid JSON in the header or payload, which can occur if the token is malformed or if the base64url decoding results in data that is not valid JSON.
        console.print(Panel(
            "[bold red]Token decoded but header or payload is not valid JSON[/bold red]\n\n"
            f"[dim]JSON error : {e.msg}[/dim]\n"
            "[dim]The token structure may be corrupted[/dim]",
            title="Parse Error",
            border_style="red"
        ))
        raise SystemExit(2)

    except ValueError as e:
        # Handle errors related to the overall structure of the JWT token, such as having an incorrect number of parts (not exactly 3), which indicates that the token is not properly formatted as a JWT.
        console.print(Panel(
            f"[bold red]{e}[/bold red]\n\n"
            "[dim]A JWT must have exactly 3 base64url parts separated by dots[/dim]\n"
            "[dim]Format : <header>.<payload>.<signature>[/dim]",
            title="Invalid Token",
            border_style="red"
        ))
        raise SystemExit(2)
