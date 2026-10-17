import binascii
import os
import time
from importlib.resources import files
from pathlib import Path

import click
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from jwt_toolkit.cli.algorithms import ensure_hmac_algorithm
from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import render_algorithm_error, resolve_token, safe_decode
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.cracker import MIN_PARALLEL_CANDIDATES, find_secret
from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS
from jwt_toolkit.core.encoding import base64_decode_padded, base64url_decode
from jwt_toolkit.core.errors import UnsupportedAlgorithmError

# Crack command — brute-forces a weak HMAC JWT secret against a wordlist.

# Expansion factor used to estimate total candidates before streaming starts.
_ENCODING_MULTIPLIER = {"utf-8": 1, "hex": 1, "base64": 1, "all": 3}

_BUNDLED_WORDLIST = "common-secrets.txt"

# Measured: beyond ~4 workers the single reader process is the bottleneck.
_DEFAULT_WORKERS = min(os.cpu_count() or 1, 4)


def _wordlist_lines(wordlist_path: str):
    # Yield each candidate line as raw bytes. Only the line terminator and a
    # leading BOM are removed: spaces, tabs, and a leading "#" can all be part
    # of a real secret. Lines are bytes so non-UTF-8 secrets are still tried.
    with Path(wordlist_path).open("rb") as f:
        for index, line in enumerate(f):
            word = line.rstrip(b"\r\n")
            if index == 0:
                word = word.removeprefix(b"\xef\xbb\xbf")
            if word:
                yield word


def _iter_candidates(wordlist_path: str, encoding: str):
    """Stream (label, secret_bytes) pairs from a wordlist file.

    Dedup is per line only (across --encoding all expansions), so memory
    stays flat however large the wordlist is.
    """
    for raw in _wordlist_lines(wordlist_path):
        word = raw.decode("utf-8", errors="replace")
        seen: set[bytes] = set()
        if encoding in ("utf-8", "all"):
            seen.add(raw)
            yield word, raw
        if encoding in ("hex", "all"):
            try:
                sbytes = bytes.fromhex(word)
            except ValueError:
                pass
            else:
                if sbytes not in seen:
                    seen.add(sbytes)
                    yield f"{word} [hex]", sbytes
        if encoding in ("base64", "all"):
            try:
                sbytes = base64_decode_padded(word)
            # Invalid base64; skip and try next candidate.
            except Exception:  # nosec B110
                pass
            else:
                if sbytes not in seen:
                    seen.add(sbytes)
                    yield f"{word} [b64]", sbytes


def _count_raw_lines(wordlist_path: str) -> int:
    """Fast pre-scan: count candidate lines."""
    return sum(1 for _ in _wordlist_lines(wordlist_path))


def _bundled_wordlist() -> Path | None:
    # Wheels ship the list as package data; a source checkout keeps it at the
    # repository root, which is where editable installs find it.
    packaged = files("jwt_toolkit") / "wordlists" / _BUNDLED_WORDLIST
    if packaged.is_file():
        return Path(str(packaged))
    checkout = Path(__file__).resolve().parents[2] / "wordlists" / _BUNDLED_WORDLIST
    return checkout if checkout.is_file() else None


def _format_rate(rate: float) -> str:
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.1f}M c/s"
    if rate >= 1_000:
        return f"{rate / 1_000:.1f}k c/s"
    return f"{rate:.0f} c/s"


@click.command(
    help=(
        "Brute-force a weak HMAC JWT secret using a wordlist. "
        "Without WORDLIST, the bundled common-secrets list is used."
    )
)
@click.argument("token")
@click.argument("wordlist", required=False, type=click.Path(exists=True, readable=True))
@click.option(
    "--workers",
    "--threads",
    "threads",
    default=_DEFAULT_WORKERS,
    show_default=True,
    type=click.IntRange(1, 64),
    help="Parallel worker processes (1-64); small wordlists run in one process",
)
@click.option(
    "--encoding",
    type=click.Choice(["utf-8", "hex", "base64", "all"]),
    default="utf-8",
    show_default=True,
    help="How to interpret each candidate before signing",
)
@click.option(
    "--output",
    default=None,
    type=click.Path(),
    help="Write found secret to this file",
)
def crack(token: str, wordlist: str | None, threads: int, encoding: str, output: str | None):
    token = resolve_token(token)
    decoded = safe_decode(token)

    if not decoded.signature:
        print_error(
            "Token has an empty signature — nothing to crack",
            "An empty signature is characteristic of an alg:none attack",
            "Use audit to examine the token structure",
            title="Cannot Crack",
        )
        raise SystemExit(2)

    try:
        alg = ensure_hmac_algorithm(decoded.header, action="crack")
    except UnsupportedAlgorithmError as exc:
        render_algorithm_error(exc)
        raise SystemExit(2) from exc

    if wordlist is None:
        bundled = _bundled_wordlist()
        if bundled is None:
            print_error(
                "No wordlist given and the bundled wordlist is missing",
                "Pass a WORDLIST path, or fetch one with: jwt-toolkit download-wordlists",
                title="Invalid Wordlist",
            )
            raise SystemExit(2)
        wordlist = str(bundled)
        if not os.environ.get("JWT_TOOLKIT_QUIET"):
            console.print("[dim]Wordlist : bundled common-secrets.txt[/dim]")

    raw_count = _count_raw_lines(wordlist)
    if raw_count == 0:
        print_error(
            "Wordlist is empty",
            f"File : {wordlist}",
            title="Invalid Wordlist",
        )
        raise SystemExit(2)

    total_estimate = raw_count * _ENCODING_MULTIPLIER.get(encoding, 1)
    workers = threads if total_estimate >= MIN_PARALLEL_CANDIDATES else 1

    try:
        signature = base64url_decode(decoded.signature)
    except binascii.Error as exc:
        print_error(
            "Token signature is not valid base64url — nothing to crack",
            title="Cannot Crack",
        )
        raise SystemExit(2) from exc

    if not os.environ.get("JWT_TOOLKIT_QUIET"):
        console.print(
            f"[dim]Algorithm : {alg}   "
            f"Candidates : ~{total_estimate:,}   "
            f"Workers : {workers}   "
            f"Encoding : {encoding}[/dim]"
        )

    result, final_attempts, elapsed = _run_crack(
        wordlist,
        encoding=encoding,
        total_estimate=total_estimate,
        workers=workers,
        alg=alg,
        header_b64=decoded.header_b64,
        payload_b64=decoded.payload_b64,
        signature=signature,
    )
    avg_rate = final_attempts / elapsed if elapsed > 0 else 0

    if result is not None:
        _render_found(result, alg, total_estimate, elapsed, avg_rate, output=output)
        raise SystemExit(1)
    _render_not_found(alg, final_attempts, elapsed, avg_rate)


def _run_crack(
    wordlist_path: str,
    *,
    encoding: str,
    total_estimate: int,
    workers: int,
    alg: str,
    header_b64: str,
    payload_b64: str,
    signature: bytes,
) -> tuple[tuple[str, int] | None, int, float]:
    digest = SUPPORTED_ALGORITHMS[alg]().name
    start = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[rate]}[/dim]"),
        TimeElapsedColumn(),
        console=console,  # type: ignore[arg-type]  # _ConsoleProxy duck-types Console
        transient=True,
    ) as progress:
        task = progress.add_task("Cracking…", total=total_estimate, rate="-")

        def on_progress(done: int) -> None:
            elapsed = time.perf_counter() - start
            rate = _format_rate(done / elapsed) if elapsed > 0 else "-"
            progress.update(task, completed=done, rate=rate)

        result = find_secret(
            _iter_candidates(wordlist_path, encoding),
            signing_input=f"{header_b64}.{payload_b64}".encode(),
            signature=signature,
            digest=digest,
            workers=workers,
            parallel=total_estimate >= MIN_PARALLEL_CANDIDATES,
            on_progress=on_progress,
        )

    elapsed = time.perf_counter() - start
    if result.label is None or result.position is None:
        return None, result.attempts, elapsed
    return (result.label, result.position), result.attempts, elapsed


def _render_found(
    result: tuple[str, int],
    alg: str,
    total_estimate: int,
    elapsed: float,
    avg_rate: float,
    *,
    output: str | None,
) -> None:
    label, idx = result
    saved_line = ""
    if output:
        try:
            with Path(output).open("w") as fout:
                fout.write(label + "\n")
            saved_line = f"\n[dim]Saved to         : {escape(output)}[/dim]"
        except OSError as exc:
            saved_line = f"\n[dim yellow]Could not save: {escape(str(exc))}[/dim yellow]"

    # Cracked = bad: the secret is dangerously weak.
    console.print(
        Panel(
            f"[bold red]Secret:[/bold red] [bold yellow]{escape(label)}[/bold yellow]{saved_line}\n\n"
            f"[dim]Algorithm        : {alg}[/dim]\n"
            f"[dim]Position         : #{idx + 1} of ~{total_estimate:,} candidates[/dim]\n"
            f"[dim]Candidates tried : {idx + 1:,}[/dim]\n"
            f"[dim]Time elapsed     : {elapsed:.3f}s[/dim]\n"
            f"[dim]Average rate     : {_format_rate(avg_rate)}[/dim]\n\n"
            "[bold red]This secret is in a common wordlist — it is not safe.[/bold red]\n"
            "[dim]Generate a strong secret with: jwt-toolkit generate-secret[/dim]",
            title="[bold red]Weak Secret Detected[/bold red]",
            border_style="red",
        )
    )


def _render_not_found(alg: str, attempts: int, elapsed: float, avg_rate: float) -> None:
    console.print(
        Panel(
            "[bold green]Secret not found in this wordlist[/bold green]\n\n"
            f"[dim]Algorithm        : {alg}[/dim]\n"
            f"[dim]Candidates tried : {attempts:,}[/dim]\n"
            f"[dim]Time elapsed     : {elapsed:.3f}s[/dim]\n"
            f"[dim]Average rate     : {_format_rate(avg_rate)}[/dim]\n\n"
            "[dim]This does not guarantee the secret is strong — a larger[/dim]\n"
            "[dim]wordlist may still find it. Use jwt-toolkit generate-secret[/dim]\n"
            "[dim]if you need a cryptographically strong secret.[/dim]",
            title="[bold green]Wordlist Check Passed[/bold green]",
            border_style="green",
        )
    )
