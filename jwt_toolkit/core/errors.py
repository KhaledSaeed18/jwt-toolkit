from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
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

    def __str__(self) -> str:
        return self.headline


@dataclass(frozen=True)
class TokenDecodeError(JwtToolkitError):
    # Raised when a token cannot be parsed into its three JSON parts.
    title: str = "Invalid Token"


@dataclass(frozen=True)
class UnsupportedAlgorithmError(JwtToolkitError):
    code: str = "unsupported_algorithm"


@dataclass(frozen=True)
class KeyPassphraseRequiredError(JwtToolkitError):
    # Raised when a PEM private key is encrypted and no passphrase was given.
    headline: str = "The private key is encrypted and needs a passphrase"
    code: str = "key_passphrase_required"
    title: str = "Key Error"


@dataclass(frozen=True)
class InvalidDurationError(JwtToolkitError):
    # Raised when a lifetime such as "15m" cannot be parsed or is out of range.
    code: str = "invalid_duration"
    title: str = "Invalid Input"


@dataclass(frozen=True)
class ClaimConflictError(JwtToolkitError):
    # Raised when a convenience option would overwrite a claim the caller set explicitly.
    code: str = "claim_conflict"
    title: str = "Invalid Input"


@dataclass(frozen=True)
class KeyParseError(JwtToolkitError):
    # The key material could not be read, decrypted, or used as a key at all.
    code: str = "key_parse_failed"
    title: str = "Key Error"


@dataclass(frozen=True)
class KeyAlgorithmMismatchError(JwtToolkitError):
    # The key is valid but belongs to a different algorithm family or curve.
    code: str = "key_algorithm_mismatch"
    title: str = "Key Error"


@dataclass(frozen=True)
class KeyNotPublicError(JwtToolkitError):
    # A private key was supplied where only the public key belongs.
    code: str = "key_not_public"
    title: str = "Key Error"


@dataclass(frozen=True)
class JwksFetchError(JwtToolkitError):
    code: str = "jwks_fetch_failed"
    title: str = "JWKS Error"


@dataclass(frozen=True)
class JwksInvalidError(JwtToolkitError):
    # The JWKS document, or a key in it, is malformed or not usable for verification.
    code: str = "jwks_invalid"
    title: str = "JWKS Error"


@dataclass(frozen=True)
class JwksNoMatchingKeyError(JwtToolkitError):
    code: str = "jwks_no_matching_key"
    title: str = "JWKS Error"


@dataclass(frozen=True)
class JwksAmbiguousError(JwtToolkitError):
    # More than one key could verify the token; guessing would be unsafe.
    code: str = "jwks_ambiguous"
    title: str = "JWKS Error"


@dataclass(frozen=True)
class ForgeVariantUnknownError(JwtToolkitError):
    code: str = "forge_variant_unknown"
    title: str = "Forge Error"


@dataclass(frozen=True)
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
