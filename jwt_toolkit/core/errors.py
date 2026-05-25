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

    def __str__(self) -> str:
        return self.headline
