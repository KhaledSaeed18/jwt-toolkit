import click
import secrets
import base64
from rich.console import Console
from rich.panel import Panel

console = Console()

@click.command()
@click.option("--bits", default=256, show_default=True, help="Secret length in bits (must be a multiple of 8)")
@click.option("--encoding", type=click.Choice(["hex", "base64"]), default="hex", show_default=True, help="Output encoding")
def generate_secret(bits: int, encoding: str):
    if bits % 8 != 0:
        raise click.UsageError("--bits must be a multiple of 8")

    raw = secrets.token_bytes(bits // 8)
    output = raw.hex() if encoding == "hex" else base64.urlsafe_b64encode(raw).decode()

    if bits >= 256:
        strength = "strong"
    elif bits >= 128:
        strength = "moderate"
    else:
        strength = "weak, use at least 128 bits"

    console.print(Panel(
        f"[bold green]{output}[/bold green]\n\n"
        f"[dim]Encoding : {encoding}[/dim]\n"
        f"[dim]Length   : {bits} bits ({bits // 8} bytes)[/dim]\n"
        f"[dim]Entropy  : {bits} bits — {strength}[/dim]",
        title="Generated Secret",
        border_style="green"
    ))
