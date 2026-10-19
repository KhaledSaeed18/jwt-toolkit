import json
import sys
import time
from pathlib import Path

import click
from click.core import ParameterSource

from jwt_toolkit.cli.algorithms import is_asymmetric, is_hmac
from jwt_toolkit.cli.credentials import SecretInputError, resolve_secret, secret_file_option
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.crypto import (
    ALL_SIGNING_ALGORITHMS,
    algorithm_for_private_key,
    canonical_algorithm,
)
from jwt_toolkit.core.crypto import (
    sign as _sign_hmac,
)
from jwt_toolkit.core.crypto import (
    sign_asymmetric as _sign_asymmetric,
)
from jwt_toolkit.core.encoding import (
    JsonObject,
    NonFiniteNumberError,
    base64url_encode,
    strict_json_loads,
)
from jwt_toolkit.core.errors import (
    ClaimConflictError,
    InvalidDurationError,
    KeyPassphraseRequiredError,
)
from jwt_toolkit.core.lifetime import parse_duration, with_lifetime

_ALG_CHOICES = sorted(ALL_SIGNING_ALGORITHMS)


@click.command(help="Mint a new JWT signed with an HMAC secret or an asymmetric private key.")
@click.option(
    "--payload",
    "payload_json",
    default=None,
    help="JWT payload as a JSON string. Mutually exclusive with --payload-file.",
)
@click.option(
    "--payload-file",
    "payload_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, allow_dash=True, path_type=Path),
    help="Read the JWT payload JSON from a file, or - for stdin.",
)
@click.option(
    "--expires-in",
    "expires_in",
    default=None,
    metavar="DURATION",
    help="Set iat to now and exp to now plus DURATION (e.g. 30s, 15m, 1h, 7d).",
)
@click.option(
    "--secret",
    default=None,
    help="HMAC secret (HS256/HS384/HS512). Mutually exclusive with --private-key.",
)
@secret_file_option
@click.option(
    "--private-key",
    "private_key_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Path to a PEM-encoded private key (RS*/PS*/ES*/Ed*). Mutually exclusive with --secret.",
)
@click.option(
    "--passphrase-file",
    "passphrase_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help=(
        "File holding the passphrase for an encrypted --private-key. "
        "Without it, an encrypted key prompts on a terminal and fails otherwise."
    ),
)
@click.option(
    "--alg",
    default="HS256",
    show_default=True,
    type=click.Choice(_ALG_CHOICES, case_sensitive=False),
    help=(
        "Signing algorithm (ignored if --header sets 'alg'). With --private-key and no "
        "--alg, it follows the key: RS256, ES256/384/512, Ed25519, or Ed448."
    ),
)
@click.option(
    "--header",
    "header_json",
    default=None,
    help='Override the JWT header as a JSON string. Default: {"alg":"<alg>","typ":"JWT"}',
)
def sign(
    *,
    payload_json: str | None,
    payload_path: Path | None,
    expires_in: str | None,
    secret: str | None,
    secret_path: Path | None,
    private_key_path: Path | None,
    passphrase_path: Path | None,
    alg: str,
    header_json: str | None,
) -> None:
    try:
        secret = resolve_secret(secret, secret_path)
    except SecretInputError as exc:
        print_error(exc.headline, *exc.details, title="Invalid Input")
        raise SystemExit(2) from exc
    payload = _parse_json_arg(_payload_text(payload_json, payload_path), label="payload")
    if expires_in is not None:
        try:
            payload = with_lifetime(
                payload, lifetime_seconds=parse_duration(expires_in), now=int(time.time())
            )
        except (InvalidDurationError, ClaimConflictError) as exc:
            print_error(f"--expires-in: {exc.headline}", *exc.details, title="Invalid Input")
            raise SystemExit(2) from exc
    header, passphrase = _resolve_header(
        None if header_json is None else _parse_json_arg(header_json, label="header"),
        alg,
        private_key_path=private_key_path if secret is None else None,
        passphrase=_read_passphrase(passphrase_path) if passphrase_path else None,
    )
    sign_alg = header["alg"]
    if not isinstance(sign_alg, str) or sign_alg not in ALL_SIGNING_ALGORITHMS:
        details = [f"Supported: {', '.join(_ALG_CHOICES)}"]
        canonical = canonical_algorithm(sign_alg) if isinstance(sign_alg, str) else None
        if canonical is not None:
            details.append(f"alg is case-sensitive; use {canonical!r} in --header")
        print_error(
            f"Unsupported algorithm: {sign_alg}",
            *details,
            title="Algorithm Error",
        )
        raise SystemExit(2)

    _validate_key_inputs(sign_alg, secret=secret, private_key_path=private_key_path)
    if passphrase_path is not None and private_key_path is None:
        print_error("--passphrase-file only applies to --private-key", title="Invalid Input")
        raise SystemExit(2)

    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if is_hmac(sign_alg):
        signature = _sign_hmac(header_b64, payload_b64, secret or "", sign_alg)
    else:
        pem_bytes = private_key_path.read_bytes()  # type: ignore[union-attr]
        try:
            try:
                signature = _sign_asymmetric(
                    header_b64, payload_b64, pem_bytes, sign_alg, passphrase=passphrase
                )
            except KeyPassphraseRequiredError:
                signature = _sign_asymmetric(
                    header_b64, payload_b64, pem_bytes, sign_alg, passphrase=_prompt_passphrase()
                )
        except ValueError as exc:
            print_error(
                "Could not sign with the provided private key",
                str(exc),
                title="Key Error",
            )
            raise SystemExit(2) from exc

    click.echo(f"{header_b64}.{payload_b64}.{signature}")


def _payload_text(payload_json: str | None, payload_path: Path | None) -> str:
    if payload_path is None and payload_json is not None:
        return payload_json
    if payload_path is None or payload_json is not None:
        print_error("Pass exactly one of --payload or --payload-file", title="Invalid Input")
        raise SystemExit(2)
    try:
        data = sys.stdin.buffer.read() if str(payload_path) == "-" else payload_path.read_bytes()
        return data.decode("utf-8-sig")
    except OSError as exc:
        print_error(
            "Cannot read --payload-file", exc.strerror or type(exc).__name__, title="Input Error"
        )
        raise SystemExit(2) from exc
    except UnicodeDecodeError as exc:
        print_error("--payload-file must contain UTF-8 JSON", title="Invalid Input")
        raise SystemExit(2) from exc


def _resolve_header(
    header: JsonObject | None,
    alg: str,
    *,
    private_key_path: Path | None,
    passphrase: bytes | None,
) -> tuple[JsonObject, bytes | None]:
    alg_chosen = click.get_current_context().get_parameter_source("alg") is not (
        ParameterSource.DEFAULT
    )
    if private_key_path is not None and not alg_chosen and (header is None or "alg" not in header):
        # The HS256 default cannot use a private key, so the key decides.
        alg, passphrase = _infer_algorithm(private_key_path.read_bytes(), passphrase)
    if header is None:
        return {"alg": alg, "typ": "JWT"}, passphrase
    if "alg" not in header:
        # The emitted header must declare the algorithm actually used to sign.
        return {"alg": alg, **header}, passphrase
    return header, passphrase


def _infer_algorithm(pem: bytes, passphrase: bytes | None) -> tuple[str, bytes | None]:
    try:
        try:
            return algorithm_for_private_key(pem, passphrase=passphrase), passphrase
        except KeyPassphraseRequiredError:
            passphrase = _prompt_passphrase()
            return algorithm_for_private_key(pem, passphrase=passphrase), passphrase
    except ValueError as exc:
        print_error("Could not use the provided private key", str(exc), title="Key Error")
        raise SystemExit(2) from exc


def _prompt_passphrase() -> bytes:
    if not _is_interactive():
        print_error(
            "The private key is encrypted",
            "Pass --passphrase-file, or run in a terminal to be prompted.",
            title="Key Error",
        )
        raise SystemExit(2)
    return click.prompt("Private key passphrase", hide_input=True, err=True).encode()


def _read_passphrase(path: Path) -> bytes:
    # Only the final line terminator is removed; other whitespace is part of it.
    data = path.read_bytes()
    return data.removesuffix(b"\n").removesuffix(b"\r")


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def _parse_json_arg(raw: str, *, label: str) -> JsonObject:
    try:
        value = strict_json_loads(raw)
    except NonFiniteNumberError as exc:
        print_error(
            f"Invalid {label} JSON",
            "NaN, Infinity, and overflowing numbers are not valid JSON.",
            title="Invalid Input",
        )
        raise SystemExit(2) from exc
    except json.JSONDecodeError as exc:
        print_error(
            f"Invalid {label} JSON",
            f"JSON error: {exc.msg}",
            title="Invalid Input",
        )
        raise SystemExit(2) from exc
    if not isinstance(value, dict):
        print_error(
            f"The {label} must be a JSON object",
            f"Got a JSON {type(value).__name__}; a JWT {label} is always an object.",
            title="Invalid Input",
        )
        raise SystemExit(2)
    return value


def _validate_key_inputs(alg: str, *, secret: str | None, private_key_path: Path | None) -> None:
    if secret is not None and private_key_path is not None:
        print_error(
            "Pass either --secret or --private-key, not both",
            title="Invalid Input",
        )
        raise SystemExit(2)

    if is_hmac(alg):
        if not secret:
            print_error(
                f"{alg} requires --secret",
                "Provide the HMAC secret to sign with.",
                title="Invalid Input",
            )
            raise SystemExit(2)
        if private_key_path is not None:
            print_error(
                f"{alg} is an HMAC algorithm: use --secret, not --private-key",
                title="Invalid Input",
            )
            raise SystemExit(2)
        return

    if is_asymmetric(alg):
        if private_key_path is None:
            print_error(
                f"{alg} requires --private-key",
                "Provide a PEM-encoded private key (PKCS#8 or traditional).",
                title="Invalid Input",
            )
            raise SystemExit(2)
        if secret is not None:
            print_error(
                f"{alg} is an asymmetric algorithm: use --private-key, not --secret",
                title="Invalid Input",
            )
            raise SystemExit(2)
