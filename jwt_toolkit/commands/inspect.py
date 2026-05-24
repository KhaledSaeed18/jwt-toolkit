import binascii
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
        
        # Display the decoded header.
        console.print(Panel(json.dumps(header, indent=2), title="Header", border_style="blue"))
        # Display the decoded payload.
        console.print(Panel(json.dumps(payload, indent=2), title="Payload", border_style="blue"))
        # Display the signature, or indicate if there is no signature (e.g., for "none" algorithm).
        console.print(Panel(signature or "(none)", title="Signature", border_style="blue"))
            
        # Perform a security audit on the decoded header and payload to identify potential issues or weaknesses in the JWT token, and collect the findings for display.    
        findings = audit(header, payload)

        # Create a table to display the audit findings with appropriate severity coloring and details for each finding.
        table = Table(title="Security Audit", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Field", width=12)
        table.add_column("Detail")

        # Iterate through the findings from the audit and add them to the table with color coding based on severity for better visualization of the results.
        for f in findings:
            color = SEVERITY_COLORS[f.severity]
            table.add_row(
                f"[{color}]{f.severity.value}[/{color}]",
                f.field,
                f.message,
            )

        # Display the audit findings in a formatted table for easy interpretation of the security issues identified in the JWT token.    
        console.print(table)

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
