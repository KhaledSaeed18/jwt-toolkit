import json
from pathlib import Path

import click
from rich.panel import Panel
from rich.table import Table

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, resolve_token, safe_decode
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.forge import (
    ALL_VARIANT_NAMES,
    KEY_BASED_VARIANT_NAMES,
    STATIC_VARIANT_NAMES,
    Variant,
    forge_one,
    generate_variants,
)

# Forge command — generates defensive test-case variants of a JWT so the user
# can confirm their verifier rejects each one. Output is grouped by variant.


_INTRO = (
    "These variants are designed to be REJECTED by a correctly configured verifier. "
    "Feed each one at your verifier and confirm it returns a failure. "
    "If any variant is accepted, the verifier has the matching vulnerability."
)


@click.command(
    help=(
        "Emit defensive attack-shaped variants of a JWT for self-audit. "
        "Every variant should be rejected by a correct verifier."
    )
)
@click.argument("token")
@click.option(
    "--public-key",
    "public_key_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help=(
        "PEM public key. Required for the hs_rs_confusion variant (CVE-2016-10555). "
        "Without it, only the key-free variants are produced."
    ),
)
@click.option(
    "--mode",
    "mode",
    default=None,
    type=click.Choice(list(ALL_VARIANT_NAMES), case_sensitive=False),
    help="Emit only the named variant instead of all of them.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a machine-readable JSON document instead of the rich table.",
)
def forge(token: str, public_key_path: Path | None, mode: str | None, as_json: bool):
    token = resolve_token(token)
    decoded = safe_decode(token, as_json=as_json)

    pem: bytes | None = public_key_path.read_bytes() if public_key_path is not None else None

    try:
        variants = _select_variants(decoded, pem=pem, mode=mode)
    except ValueError as exc:
        print_error(str(exc), title="Forge Error")
        raise SystemExit(2) from exc

    if as_json:
        _emit_json(variants, has_public_key=pem is not None)
    else:
        _emit_rich(variants, has_public_key=pem is not None)


def _select_variants(decoded, *, pem: bytes | None, mode: str | None) -> list[Variant]:
    if mode is not None:
        return [forge_one(mode, decoded, public_key_pem=pem)]
    names = STATIC_VARIANT_NAMES if pem is None else STATIC_VARIANT_NAMES + KEY_BASED_VARIANT_NAMES
    return generate_variants(decoded, public_key_pem=pem, names=names)


def _emit_json(variants: list[Variant], *, has_public_key: bool) -> None:
    document = {
        "schema_version": JSON_SCHEMA_VERSION,
        "intent": "defensive_test_cases",
        "expected_outcome": "every variant must be rejected by the verifier under test",
        "public_key_supplied": has_public_key,
        "variants": [
            {
                "name": v.name,
                "description": v.description,
                "cve": v.cve,
                "token": v.token,
            }
            for v in variants
        ],
    }
    click.echo(json.dumps(document, indent=2))


def _emit_rich(variants: list[Variant], *, has_public_key: bool) -> None:
    console.print(Panel(_INTRO, title="Forge — defensive test cases", border_style="blue"))

    table = Table(title="Variants", show_lines=True)
    table.add_column("Name", style="bold", width=20)
    table.add_column("CVE", style="dim", width=14)
    table.add_column("Description")
    for v in variants:
        table.add_row(v.name, v.cve or "—", v.description)
    console.print(table)

    for v in variants:
        cve_suffix = f"  [dim]({v.cve})[/dim]" if v.cve else ""
        console.print(
            Panel(
                v.token,
                title=f"[bold]{v.name}[/bold]{cve_suffix}",
                border_style="yellow",
            )
        )

    if not has_public_key:
        console.print(
            Panel(
                "[dim]Pass --public-key to also emit the hs_rs_confusion variant "
                "(CVE-2016-10555).[/dim]",
                border_style="cyan",
            )
        )
