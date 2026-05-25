import binascii
import click
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.auditor import audit, Severity

# Inspect command — decodes a JWT and runs the security auditor on it.

console = Console()

# Map severity levels to display colors.
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "cyan",
    Severity.PASS: "green",
}

@click.command()
@click.argument("token")
def inspect(token: str):
    # Decode and audit a JWT.
    try:
        # Decode the token into its three components.
        header, payload, signature = decode_token(token)

        console.print(Panel(json.dumps(header, indent=2), title="Header", border_style="blue"))
        console.print(Panel(json.dumps(payload, indent=2), title="Payload", border_style="blue"))
        # Show "(none)" for unsigned tokens instead of an empty panel.
        console.print(Panel(signature or "(none)", title="Signature", border_style="blue"))

        # Run the security auditor and display findings.
        findings = audit(header, payload)

        table = Table(title="Security Audit", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Field", width=12)
        table.add_column("Detail")

        for f in findings:
            color = SEVERITY_COLORS[f.severity]
            table.add_row(f"[{color}]{f.severity.value}[/{color}]", f.field, f.message)

        console.print(table)

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
