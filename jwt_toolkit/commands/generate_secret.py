import base64
import secrets
from collections.abc import Callable

import click

from jwt_toolkit.cli.panels import print_error, print_success

# Generate-secret command — emits a cryptographically strong random secret in
# hex or base64, with a strength label derived from the bit length.


# (headline, predicate, suggestion) — first match wins. `suggestion` may be a
# callable for rules whose hint depends on the actual value passed.
_VALIDATIONS: tuple[tuple[str, Callable[[int], bool], str | Callable[[int], str]], ...] = (
    ("--bits must be a positive number", lambda b: b <= 0, "Try instead : 256 bits"),
    ("--bits must be 4096 or fewer", lambda b: b > 4096, "Maximum     : 4096 bits"),
    ("--bits is too small to be secure", lambda b: b < 64, "Minimum     : 64 bits"),
    (
        "--bits must be a multiple of 8",
        lambda b: b % 8 != 0,
        lambda b: f"Try instead : {(b // 8 + 1) * 8} bits",
    ),
)


def _validate_bits(bits: int) -> None:
    for headline, predicate, suggestion in _VALIDATIONS:
        if not predicate(bits):
            continue
        hint = suggestion(bits) if callable(suggestion) else suggestion
        print_error(
            headline,
            f"You passed  : {bits} bits",
            hint,
            title="Invalid Input",
        )
        raise SystemExit(2)


def _strength_for(bits: int) -> str:
    if bits >= 256:
        return "strong"
    if bits >= 128:
        return "moderate"
    return "weak, use at least 128 bits"


@click.command(help="Generate a cryptographically strong random secret for signing JWTs.")
@click.option(
    "--bits", default=256, show_default=True, help="Secret length in bits (must be a multiple of 8)"
)
@click.option(
    "--encoding",
    type=click.Choice(["hex", "base64"]),
    default="hex",
    show_default=True,
    help="Output encoding (base64 is URL-safe with padding)",
)
@click.option(
    "--raw",
    is_flag=True,
    help="Print only the secret and a newline, for scripts and files.",
)
def generate_secret(bits: int, encoding: str, raw: bool):
    _validate_bits(bits)

    secret = secrets.token_bytes(bits // 8)
    output = secret.hex() if encoding == "hex" else base64.urlsafe_b64encode(secret).decode()

    # --raw bypasses the Rich console so --quiet and --no-color cannot hide or style it.
    if raw:
        click.echo(output)
        return

    print_success(
        output,
        f"Encoding : {encoding}",
        f"Length   : {bits} bits ({bits // 8} bytes)",
        f"Entropy  : {bits} bits — {_strength_for(bits)}",
        title="Generated Secret",
    )
