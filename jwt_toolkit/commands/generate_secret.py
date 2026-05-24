import click
import secrets
import base64
from rich.console import Console
from rich.panel import Panel

# Command to generate a random secret key for signing JWTs, with options for specifying the length in bits and the output encoding format (hex or base64).
# The command also provides feedback on the strength of the generated secret based on its length.

console = Console()

@click.command()
@click.option("--bits", default=256, show_default=True, help="Secret length in bits (must be a multiple of 8)")
@click.option("--encoding", type=click.Choice(["hex", "base64"]), default="hex", show_default=True, help="Output encoding")
def generate_secret(bits: int, encoding: str):
    # Check if the number of bits is a positive integer, and provide an error message if it is not.
    if bits <= 0:
        console.print(Panel(
            "[bold red]--bits must be a positive number[/bold red]\n\n"
            f"[dim]You passed  : {bits} bits[/dim]\n"
            f"[dim]Try instead : 256 bits[/dim]",
            title="Invalid Input",
            border_style="red"
        ))
        raise SystemExit(2)

    # Check if the number of bits is less than or equal to 4096, and provide an error message if it exceeds this limit, as excessively long secrets may not be practical or necessary for most JWT use cases.
    if bits > 4096:
        console.print(Panel(
            "[bold red]--bits must be 4096 or fewer[/bold red]\n\n"
            f"[dim]You passed  : {bits} bits[/dim]\n"
            f"[dim]Maximum     : 4096 bits[/dim]",
            title="Invalid Input",
            border_style="red"
        ))
        raise SystemExit(2)

    # Check if the number of bits is less than 64, and provide an error message if it is too small to be secure, as secrets with insufficient entropy can be easily brute-forced.
    if bits < 64:
        console.print(Panel(
            "[bold red]--bits is too small to be secure[/bold red]\n\n"
            f"[dim]You passed  : {bits} bits[/dim]\n"
            f"[dim]Minimum     : 64 bits[/dim]",
            title="Invalid Input",
            border_style="red"
        ))
        raise SystemExit(2)

    # Check if the number of bits is a multiple of 8, and provide an error message if it is not, as secrets are typically generated in whole bytes (8 bits), and non-multiple of 8 values may lead to confusion or incorrect secret lengths.
    if bits % 8 != 0:
        console.print(Panel(
            "[bold red]--bits must be a multiple of 8[/bold red]\n\n"
            f"[dim]You passed  : {bits} bits[/dim]\n"
            f"[dim]Try instead : {(bits // 8 + 1) * 8} bits[/dim]",
            title="Invalid Input",
            border_style="red"
        ))
        raise SystemExit(2)

    # Generate a random secret key using the secrets module, which provides a secure way to generate random bytes.
    # The length of the secret is determined by the specified number of bits, and the output is encoded in either hexadecimal or base64 format based on the user's choice.
    raw = secrets.token_bytes(bits // 8)
    output = raw.hex() if encoding == "hex" else base64.urlsafe_b64encode(raw).decode()

    # Calculate the strength of the secret based on its length
    if bits >= 256:
        strength = "strong"
    elif bits >= 128:
        strength = "moderate"
    else:
        strength = "weak, use at least 128 bits"

    # Display the generated secret along with its encoding, length in bits and bytes, and an assessment of its strength in a formatted panel for better readability.
    console.print(Panel(
        f"[bold green]{output}[/bold green]\n\n"
        f"[dim]Encoding : {encoding}[/dim]\n"
        f"[dim]Length   : {bits} bits ({bits // 8} bytes)[/dim]\n"
        f"[dim]Entropy  : {bits} bits — {strength}[/dim]",
        title="Generated Secret",
        border_style="green"
    ))
