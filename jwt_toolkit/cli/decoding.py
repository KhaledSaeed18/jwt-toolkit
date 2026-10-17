import json
import sys
from collections.abc import Callable
from pathlib import Path

import click

from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.decoder import DecodedToken, decode_token
from jwt_toolkit.core.errors import TokenDecodeError, UnsupportedAlgorithmError

# Stable schema version shared by every command that emits --json errors.
JSON_SCHEMA_VERSION = "0.1"


def resolve_token(raw: str, *, as_json: bool = False) -> str:
    """Resolve the token string from a raw CLI argument.

    Accepts three forms:
      -        read from stdin
      @<path>  read from a file
      <token>  use as-is
    """
    if raw == "-":
        return sys.stdin.read().strip()
    if raw.startswith("@"):
        path = raw[1:]
        try:
            with Path(path).open() as fh:
                return fh.read().strip()
        except OSError as exc:
            if as_json:
                _emit_error(
                    code="token_unreadable",
                    title="Input Error",
                    headline=f"Cannot read token from {path!r}",
                    details=(exc.strerror or type(exc).__name__,),
                    as_json=True,
                    extra=None,
                )
            else:
                click.echo(f"Cannot read token from {path!r}: {exc}", err=True)
            raise SystemExit(2) from exc
    return raw


def safe_decode(
    token: str,
    *,
    as_json: bool = False,
    json_extra: Callable[[TokenDecodeError], dict] | None = None,
) -> DecodedToken:
    # Decode a token, rendering a consistent error panel/JSON on failure and
    # exiting with code 2. The caller never has to know about the exception types.
    try:
        return decode_token(token)
    except TokenDecodeError as exc:
        _emit_error(
            code=exc.code,
            title=exc.title,
            headline=exc.headline,
            details=exc.details,
            as_json=as_json,
            extra=json_extra(exc) if json_extra else None,
        )
        raise SystemExit(2) from exc


def emit_error(
    *,
    code: str,
    title: str,
    headline: str,
    details: tuple[str, ...] = (),
    as_json: bool,
    extra: dict | None = None,
) -> None:
    # Public entry for commands: a JSON envelope under --json, a panel otherwise.
    _emit_error(
        code=code, title=title, headline=headline, details=details, as_json=as_json, extra=extra
    )


def render_algorithm_error(exc: UnsupportedAlgorithmError) -> None:
    print_error(exc.headline, *exc.details, title=exc.title)


def _emit_error(
    *,
    code: str,
    title: str,
    headline: str,
    details: tuple[str, ...],
    as_json: bool,
    extra: dict | None,
) -> None:
    if as_json:
        document = {
            "schema_version": JSON_SCHEMA_VERSION,
            "error": code,
            "message": headline,
            "detail": list(details),
        }
        if extra:
            document.update(extra)
        click.echo(json.dumps(document, indent=2))
        return
    print_error(headline, *details, title=title)
