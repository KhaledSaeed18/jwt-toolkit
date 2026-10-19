import hashlib
import hmac
import http.client
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import click
from rich.markup import escape
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from jwt_toolkit.cli.console import console, err_console, status_console
from jwt_toolkit.cli.panels import print_error, print_success


def _release_ref() -> str:
    try:
        return f"v{version('jwt-toolkit')}"
    except PackageNotFoundError:
        return "main"


# Pinned to the release tag so the checksum below always matches the content;
# a wordlist update on main must not break integrity checks in older releases.
_WORDLIST_URL = (
    "https://raw.githubusercontent.com/KhaledSaeed18/jwt-toolkit/"
    f"{_release_ref()}/wordlists/common-secrets.txt"
)
_FILENAME = "common-secrets.txt"

_PERMITTED_SOURCE_SCHEMES = frozenset({"https", "http", "file"})

# SHA-256 of the bundled wordlist at _WORDLIST_URL. Verified against local copy.
# Only used when downloading from the default URL; custom --source URLs skip this check.
_WORDLIST_SHA256 = "1b4bae820e98073b7148412425ea27e00cd1c4d0900ad446bdae146665ea758a"


def _open_url(url: str) -> http.client.HTTPResponse:
    # Certificate failures must stay fatal: there is no unverified fallback.
    response: http.client.HTTPResponse = urllib.request.urlopen(url, timeout=30)  # nosec B310 - scheme checked by the caller
    return response


class _DownloadError(Exception):
    def __init__(self, headline: str, *details: str) -> None:
        super().__init__(headline)
        self.headline = headline
        self.details = details


def _download(url: str, dest_dir: Path) -> tuple[Path, int]:
    # Streams into a temporary file beside the destination, so a failed or
    # interrupted download never replaces (or deletes) a good existing copy.
    try:
        response = _open_url(url)
    except urllib.error.HTTPError as exc:
        raise _DownloadError(f"The server answered HTTP {exc.code} {exc.reason}", url) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise _DownloadError(
                "TLS certificate verification failed, the download cannot be trusted",
                "If a proxy re-signs TLS traffic, point SSL_CERT_FILE at its CA bundle.",
            ) from exc
        reason = getattr(exc.reason, "strerror", None) or str(exc.reason)
        raise _DownloadError("Could not reach the download source", reason) from exc
    except (OSError, ValueError) as exc:
        raise _DownloadError("Could not reach the download source", str(exc)) from exc

    try:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{_FILENAME}.", suffix=".part", dir=dest_dir)
    except OSError:
        response.close()
        raise
    tmp = Path(tmp_name)
    written = 0
    try:
        with (
            os.fdopen(fd, "wb") as f,
            Progress(
                SpinnerColumn(),
                TextColumn("[bold]common-secrets.txt[/bold]"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                TimeElapsedColumn(),
                console=status_console,  # type: ignore[arg-type]  # _ConsoleProxy duck-types Console
                transient=True,
            ) as progress,
        ):
            content_length = response.headers.get("Content-Length")
            task = progress.add_task(
                "Downloading…", total=int(content_length) if content_length else None
            )
            while chunk := response.read(65_536):
                f.write(chunk)
                written += len(chunk)
                progress.update(task, advance=len(chunk))
    except (OSError, http.client.HTTPException) as exc:
        tmp.unlink(missing_ok=True)
        raise _DownloadError(
            "The download was interrupted", str(exc) or type(exc).__name__
        ) from exc
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        response.close()
    return tmp, written


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as f:
        for _ in f:
            count += 1
    return count


def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1_024:
        return f"{n / 1_024:.1f} KB"
    return f"{n} B"


@click.command(
    "download-wordlists",
    help=(
        "Download the common-secrets wordlist for this release.\n\n"
        "Fetches common-secrets.txt from the jwt-toolkit repository at the tag "
        "matching the installed version, and verifies its checksum."
    ),
)
@click.option(
    "--output-dir",
    default="wordlists",
    show_default=True,
    type=click.Path(),
    help="Directory to save the wordlist",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing file without prompting",
)
@click.option(
    "--source",
    default=None,
    metavar="URL",
    help=(
        "Custom URL to download from instead of the default jwt-toolkit repository. "
        "Integrity verification is skipped for custom sources."
    ),
)
def download_wordlists(output_dir: str, force: bool, source: str | None) -> None:
    url = source or _WORDLIST_URL
    verify_integrity = source is None

    dest_dir = Path(output_dir).resolve()

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print_error(
            "Cannot create output directory",
            f"Path  : {dest_dir}",
            f"Error : {exc.strerror}",
            title="Directory Error",
        )
        raise SystemExit(2) from exc

    dest = dest_dir / _FILENAME

    if dest.exists() and not force:
        size = dest.stat().st_size
        console.print(
            f"[yellow]Already exists:[/yellow] {escape(str(dest))} ({_fmt_bytes(size)})\n"
            f"[dim]Use --force to download it again[/dim]"
        )
        return

    if source:
        scheme = urllib.parse.urlparse(source).scheme
        if scheme not in _PERMITTED_SOURCE_SCHEMES:
            print_error(
                f"--source scheme {scheme!r} is not supported",
                "Use an https://, http://, or file:// URL.",
                title="Invalid Input",
            )
            raise SystemExit(2)
        status_console.print(f"[dim]Source   : {escape(url)}[/dim]")
    status_console.print(f"[dim]Saving to: {escape(str(dest))}[/dim]")

    try:
        tmp, written = _download(url, dest_dir)
    except KeyboardInterrupt:
        err_console.print("[yellow]Download cancelled[/yellow]")
        raise SystemExit(1) from None
    except _DownloadError as exc:
        print_error(exc.headline, *exc.details, title="Download Failed")
        raise SystemExit(1) from exc
    except OSError as exc:
        print_error(
            "Could not write the wordlist",
            f"Path  : {dest_dir}",
            f"Error : {exc.strerror or type(exc).__name__}",
            title="Write Error",
        )
        raise SystemExit(2) from exc

    if verify_integrity:
        actual = _sha256(tmp)
        if not hmac.compare_digest(actual, _WORDLIST_SHA256):
            tmp.unlink(missing_ok=True)
            print_error(
                "Integrity check failed, the download was discarded",
                f"Expected : {_WORDLIST_SHA256}",
                f"Got      : {actual}",
                "The downloaded file does not match the pinned checksum.",
                "This may indicate a compromised source or a wordlist update.",
                "If the wordlist was intentionally updated, report this at "
                "https://github.com/KhaledSaeed18/jwt-toolkit/issues",
                title="Integrity Error",
            )
            raise SystemExit(2)

    tmp.replace(dest)
    lines = _count_lines(dest)

    print_success(
        _FILENAME,
        f"Saved to : {dest}",
        f"Size     : {_fmt_bytes(written)}",
        f"Entries  : {lines:,} {'line' if lines == 1 else 'lines'}",
        *([f"Checksum : {_WORDLIST_SHA256}  ✓"] if verify_integrity else []),
        title="[bold green]Downloaded[/bold green]",
        footer=(
            "[dim]Use with crack:[/dim]",
            f"[bold]jwt-toolkit crack <token> {escape(str(dest))}[/bold]",
        ),
    )
