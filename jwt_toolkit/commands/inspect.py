import click
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.auditor import audit, Severity

# Command to inspect a JWT token, decode its components, and perform a security audit based on the decoded header and payload.

console = Console()

# Define severity levels for findings in the audit process, which can be used to categorize and display the results of the audit in a user-friendly manner.
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "cyan",
    Severity.PASS: "green",
}


@click.command()
@click.argument("token")
def inspect(token: str):
    try:
        # Decode the JWT token to extract its header, payload, and signature components.
        header, payload, signature = decode_token(token)
        
        console.print(Panel(json.dumps(header, indent=2), title="Header", border_style="blue"))
        console.print(Panel(json.dumps(payload, indent=2), title="Payload", border_style="blue"))
        console.print(Panel(signature or "(none)", title="Signature", border_style="blue"))

        findings = audit(header, payload)

        table = Table(title="Security Audit", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Field", width=12)
        table.add_column("Detail")

        for f in findings:
            color = SEVERITY_COLORS[f.severity]
            table.add_row(
                f"[{color}]{f.severity.value}[/{color}]",
                f.field,
                f.message,
            )

        console.print(table)

    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
