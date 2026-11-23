from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar, cast, dataclass_transform
from urllib.parse import urlsplit, urlunsplit

# Python sets these on an exception as it propagates (contextlib, `raise ... from`).
_EXCEPTION_STATE = frozenset(
    {"__traceback__", "__cause__", "__context__", "__suppress_context__", "__notes__"}
)


@dataclass_transform(frozen_default=True)
def frozen_error[E: type[BaseException]](cls: E) -> E:
    # A frozen dataclass for an exception: its fields cannot change, but the
    # traceback and chaining state Python manages still can.
    frozen = cast(E, dataclass(frozen=True)(cls))
    frozen_setattr: Callable[[Any, str, Any], None] = frozen.__setattr__

    def __setattr__(self: Any, name: str, value: Any) -> None:
        if name in _EXCEPTION_STATE:
            BaseException.__setattr__(self, name, value)
        else:
            frozen_setattr(self, name, value)

    type.__setattr__(frozen, "__setattr__", __setattr__)
    return frozen


@frozen_error
class JwtToolkitError(ValueError):
    # Base of every failure jwt-toolkit reports. A ValueError, so callers that
    # caught ValueError from core before the typed errors existed still catch them.
    #
    # `code` is the stable machine-readable id --json consumers key off; codes are
    # never renamed or reused. `headline` and `details` are short, security-outcome
    # shaped, and never carry secrets, key material or credential-bearing URLs.
    # `cause` holds the more specific code when a command reports a broad one (for
    # example `key_error` caused by `key_parse_failed`). `extra` adds fields to the
    # --json error document.
    headline: str
    details: tuple[str, ...] = ()
    code: str = "error"
    title: str = "Error"
    cause: str | None = None
    extra: tuple[tuple[str, str], ...] = ()

    # Process exit code when the CLI reports this error: 2 means the input, key or
    # options could not be used. Not a field, so it never reaches --json.
    exit_code: ClassVar[int] = 2

    def __str__(self) -> str:
        return self.headline


@frozen_error
class TokenDecodeError(JwtToolkitError):
    # Raised when a token cannot be parsed into its three JSON parts.
    title: str = "Invalid Token"


@frozen_error
class UnsupportedAlgorithmError(JwtToolkitError):
    code: str = "unsupported_algorithm"


@frozen_error
class KeyPassphraseRequiredError(JwtToolkitError):
    # Raised when a PEM private key is encrypted and no passphrase was given.
    headline: str = "The private key is encrypted and needs a passphrase"
    code: str = "key_passphrase_required"
    title: str = "Key Error"


@frozen_error
class InvalidDurationError(JwtToolkitError):
    # Raised when a lifetime such as "15m" cannot be parsed or is out of range.
    code: str = "invalid_duration"
    title: str = "Invalid Input"


@frozen_error
class ClaimConflictError(JwtToolkitError):
    # Raised when a convenience option would overwrite a claim the caller set explicitly.
    code: str = "claim_conflict"
    title: str = "Invalid Input"


@frozen_error
class KeyParseError(JwtToolkitError):
    # The key material could not be read, decrypted, or used as a key at all.
    code: str = "key_parse_failed"
    title: str = "Key Error"


@frozen_error
class KeyAlgorithmMismatchError(JwtToolkitError):
    # The key is valid but belongs to a different algorithm family or curve.
    code: str = "key_algorithm_mismatch"
    title: str = "Key Error"


@frozen_error
class KeyNotPublicError(JwtToolkitError):
    # A private key was supplied where only the public key belongs.
    code: str = "key_not_public"
    title: str = "Key Error"


@frozen_error
class JwksFetchError(JwtToolkitError):
    code: str = "jwks_fetch_failed"
    title: str = "JWKS Error"


@frozen_error
class JwksInvalidError(JwtToolkitError):
    # The JWKS document, or a key in it, is malformed or not usable for verification.
    code: str = "jwks_invalid"
    title: str = "JWKS Error"


@frozen_error
class JwksNoMatchingKeyError(JwtToolkitError):
    code: str = "jwks_no_matching_key"
    title: str = "JWKS Error"


@frozen_error
class JwksAmbiguousError(JwtToolkitError):
    # More than one key could verify the token; guessing would be unsafe.
    code: str = "jwks_ambiguous"
    title: str = "JWKS Error"


@frozen_error
class ForgeVariantUnknownError(JwtToolkitError):
    code: str = "forge_variant_unknown"
    title: str = "Forge Error"


@frozen_error
class ForgeVariantNeedsKeyError(JwtToolkitError):
    code: str = "forge_variant_needs_key"
    title: str = "Forge Error"


def redact_url(url: str) -> str:
    # Drops userinfo, query and fragment, which may carry credentials or tokens,
    # so a URL can appear in an error message.
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "<unparseable URL>"
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))
