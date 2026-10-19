from dataclasses import dataclass


@dataclass(frozen=True)
class TokenDecodeError(Exception):
    # Raised when a token cannot be parsed into its three JSON parts.
    # `code` is the stable machine-readable id used by --json consumers;
    # `title`/`headline`/`details` drive the human-readable panel.
    code: str
    title: str
    headline: str
    details: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.headline


@dataclass(frozen=True)
class UnsupportedAlgorithmError(Exception):
    title: str
    headline: str
    details: tuple[str, ...] = ()
    code: str = "unsupported_algorithm"

    def __str__(self) -> str:
        return self.headline


@dataclass(frozen=True)
class KeyPassphraseRequiredError(ValueError):
    # Raised when a PEM private key is encrypted and no passphrase was given.
    # A ValueError so existing "key could not be used" handlers still catch it.
    headline: str = "The private key is encrypted and needs a passphrase"
    code: str = "key_passphrase_required"

    def __str__(self) -> str:
        return self.headline


@dataclass(frozen=True)
class InvalidDurationError(ValueError):
    # Raised when a lifetime such as "15m" cannot be parsed or is out of range.
    headline: str
    details: tuple[str, ...] = ()
    code: str = "invalid_duration"

    def __str__(self) -> str:
        return self.headline


@dataclass(frozen=True)
class ClaimConflictError(ValueError):
    # Raised when a convenience option would overwrite a claim the caller set explicitly.
    headline: str
    details: tuple[str, ...] = ()
    code: str = "claim_conflict"

    def __str__(self) -> str:
        return self.headline
