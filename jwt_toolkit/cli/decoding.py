import sys
from pathlib import Path

from jwt_toolkit.cli.errors import JSON_SCHEMA_VERSION, render_error
from jwt_toolkit.core.decoder import MAX_TOKEN_BYTES, DecodedToken, check_token_size, decode_token
from jwt_toolkit.core.encoding import JsonObject
from jwt_toolkit.core.errors import JwtToolkitError

__all__ = ["JSON_SCHEMA_VERSION", "emit_error", "resolve_token", "safe_decode"]


def resolve_token(raw: str) -> str:
    """Resolve the token string from a raw CLI argument.

    Accepts three forms:
      -        read from stdin
      @<path>  read from a file
      <token>  use as-is

    A leading "Bearer " is dropped, so a value copied from an Authorization
    header works as-is.
    """
    # Reads stop just past the limit, so a huge stdin or file is never loaded whole.
    if raw == "-":
        return _strip_bearer(_bounded(sys.stdin.read(MAX_TOKEN_BYTES + 1)))
    if raw.startswith("@"):
        path = raw[1:]
        try:
            with Path(path).open("rb") as handle:
                data = handle.read(MAX_TOKEN_BYTES + 1)
            check_token_size(len(data))
            return _strip_bearer(data.decode("utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            reason = (
                "The file is not UTF-8 text"
                if isinstance(exc, UnicodeDecodeError)
                else exc.strerror or type(exc).__name__
            )
            raise JwtToolkitError(
                headline=f"Cannot read token from {path!r}",
                details=(reason,),
                code="token_unreadable",
                title="Input Error",
            ) from exc
    return _strip_bearer(_bounded(raw))


def _bounded(value: str) -> str:
    check_token_size(len(value.encode("utf-8", errors="surrogatepass")))
    return value


def _strip_bearer(value: str) -> str:
    # RFC 6750 2.1: the auth scheme name is case-insensitive.
    value = value.strip()
    scheme, _, rest = value.partition(" ")
    return rest.strip() if scheme.lower() == "bearer" and rest else value


def safe_decode(token: str, *, tolerate_whitespace: bool = False) -> DecodedToken:
    # A TokenDecodeError reaches the command's error boundary, which renders it.
    return decode_token(token, tolerate_whitespace=tolerate_whitespace)


def emit_error(
    *,
    code: str,
    title: str,
    headline: str,
    details: tuple[str, ...] = (),
    as_json: bool,
    extra: JsonObject | None = None,
) -> None:
    # For a command that reports an error and still exits with its own result code.
    render_error(
        JwtToolkitError(
            headline=headline,
            details=details,
            code=code,
            title=title,
            extra=tuple((k, str(v)) for k, v in (extra or {}).items()),
        ),
        as_json=as_json,
    )
