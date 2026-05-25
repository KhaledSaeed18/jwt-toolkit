import ssl
import urllib.error
import urllib.request
from pathlib import Path
import click
from rich.console import Console
from rich.panel import Panel
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

# Download command — fetches the latest common-secrets wordlist from the jwt-toolkit repo.

console = Console()

_WORDLIST_URL = (
    "https://raw.githubusercontent.com/KhaledSaeed18/jwt-toolkit/main"
    "/wordlists/common-secrets.txt"
)
_FILENAME = "common-secrets.txt"


def _open_url(url: str):
    # Open a URL, falling back to an unverified context on macOS cert issues.
    try:
        return urllib.request.urlopen(url, timeout=30)
    except ssl.SSLCertVerificationError:
        ctx = ssl._create_unverified_context()
        return urllib.request.urlopen(url, context=ctx, timeout=30)


def _download(url: str, dest: Path) -> int:
    # Stream URL to dest with a Rich progress bar. Returns bytes written.
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]common-secrets.txt[/bold]"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        try:
            response = _open_url(url)
        except urllib.error.HTTPError as exc:
            raise click.ClickException(f"HTTP {exc.code} {exc.reason}: {url}") from exc
        except urllib.error.URLError as exc:
            raise click.ClickException(f"Network error: {exc.reason}") from exc

        content_length = response.headers.get("Content-Length")
        total = int(content_length) if content_length else None
        task = progress.add_task("Downloading…", total=total)

        written = 0
        try:
            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(65_536)
                    if not chunk:
                        break
                    f.write(chunk)
                    written += len(chunk)
                    progress.update(task, advance=len(chunk))
        except KeyboardInterrupt:
            dest.unlink(missing_ok=True)
            console.print("\n[yellow]Download cancelled[/yellow]")
            raise SystemExit(1)

    return written


def _count_lines(path: Path) -> int:
    count = 0
    with open(path, "rb") as f:
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
        "Download the latest common-secrets wordlist.\n\n"
        "Fetches common-secrets.txt from the jwt-toolkit repository "
        "so you always have the most up-to-date list of weak JWT secrets."
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
def download_wordlists(output_dir: str, force: bool):
    dest_dir = Path(output_dir).resolve()

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(Panel(
            f"[bold red]Cannot create output directory[/bold red]\n\n"
            f"[dim]Path  : {dest_dir}[/dim]\n"
            f"[dim]Error : {exc.strerror}[/dim]",
            title="Directory Error",
            border_style="red",
        ))
        raise SystemExit(2)

    dest = dest_dir / _FILENAME

    if dest.exists() and not force:
        size = dest.stat().st_size
        console.print(
            f"[yellow]Already exists:[/yellow] {dest} ({_fmt_bytes(size)})\n"
            f"[dim]Use --force to overwrite with the latest version[/dim]"
        )
        return

    console.print(f"[dim]Saving to : {dest}[/dim]")

    try:
        written = _download(_WORDLIST_URL, dest)
    except click.ClickException:
        raise
    except OSError as exc:
        console.print(Panel(
            f"[bold red]Could not write file[/bold red]\n\n"
            f"[dim]Path  : {dest}[/dim]\n"
            f"[dim]Error : {exc}[/dim]",
            title="Write Error",
            border_style="red",
        ))
        raise SystemExit(2)

    lines = _count_lines(dest)

    console.print(Panel(
        f"[bold green]{_FILENAME}[/bold green]\n\n"
        f"[dim]Saved to : {dest}[/dim]\n"
        f"[dim]Size     : {_fmt_bytes(written)}[/dim]\n"
        f"[dim]Entries  : {lines:,} lines[/dim]\n\n"
        f"[dim]Use with crack:[/dim]\n"
        f"[bold]jwt-toolkit crack <token> {dest}[/bold]",
        title="[bold green]Downloaded[/bold green]",
        border_style="green",
    ))
