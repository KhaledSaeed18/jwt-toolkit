from dataclasses import dataclass, field
from pathlib import Path

import click

SECRET_FILE_HELP = (
    "File holding the HMAC secret as UTF-8 text, so it stays out of shell history. "
    "One trailing newline is ignored. Mutually exclusive with --secret."
)


@dataclass(frozen=True)
class SecretInputError(Exception):
    # Messages name the flag only; they never include secret material.
    headline: str
    details: tuple[str, ...] = field(default=())

    def __str__(self) -> str:
        return self.headline


secret_file_option = click.option(
    "--secret-file",
    "secret_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help=SECRET_FILE_HELP,
)


def resolve_secret(secret: str | None, secret_path: Path | None) -> str | None:
    if secret_path is None:
        return secret
    if secret is not None:
        raise SecretInputError("Pass either --secret or --secret-file, not both")
    try:
        data = secret_path.read_bytes()
    except OSError as exc:
        raise SecretInputError(
            "Cannot read --secret-file", (exc.strerror or type(exc).__name__,)
        ) from exc
    # Strip only what editors and `generate-secret --raw` add; other whitespace is part of the key.
    data = data.removeprefix(b"\xef\xbb\xbf").removesuffix(b"\n").removesuffix(b"\r")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretInputError(
            "--secret-file must contain UTF-8 text",
            ("The file is used as text, the same way --secret is.",),
        ) from exc
    if not text:
        raise SecretInputError("--secret-file is empty")
    return text
