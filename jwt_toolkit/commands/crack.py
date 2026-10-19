import binascii
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

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
from jwt_toolkit.cli.console import console, status_console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, emit_error, resolve_token, safe_decode
from jwt_toolkit.cli.wordlists import BUNDLED_WORDLIST_NAME, bundled_wordlist
from jwt_toolkit.core.cracker import MIN_PARALLEL_CANDIDATES, find_secret
from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS
from jwt_toolkit.core.encoding import base64url_decode
from jwt_toolkit.core.errors import UnsupportedAlgorithmError
from jwt_toolkit.core.wordlist import (
    ENCODING_MULTIPLIER,
    ENCODINGS,
    Candidate,
    count_lines,
    iter_candidates,
)

# Measured: beyond ~4 workers the single reader process is the bottleneck.
_DEFAULT_WORKERS = min(os.cpu_count() or 1, 4)


@dataclass(frozen=True)
class _Outcome:
    alg: str
    encoding: str
    wordlist: str
    total_estimate: int
    attempts: int
    elapsed: float
    match: Candidate | None
    position: int | None

    @property
    def rate(self) -> float:
        return self.attempts / self.elapsed if self.elapsed > 0 else 0


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
@click.argument(
    "wordlist",
    required=False,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
)
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
    type=click.Choice(ENCODINGS),
    default="utf-8",
    show_default=True,
    help="How to interpret each candidate before signing",
)
@click.option(
    "--output",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the found secret to this file (created owner-readable only)",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
def crack(
    token: str,
    wordlist: Path | None,
    *,
    threads: int,
    encoding: str,
    output: Path | None,
    as_json: bool,
) -> None:
    token = resolve_token(token, as_json=as_json)
    decoded = safe_decode(token, as_json=as_json)

    def fail(code: str, headline: str, *details: str, title: str = "Cannot Crack") -> NoReturn:
        emit_error(code=code, title=title, headline=headline, details=details, as_json=as_json)
        raise SystemExit(2)

    try:
        alg = ensure_hmac_algorithm(decoded.header, action="crack")
    except UnsupportedAlgorithmError as exc:
        emit_error(
            code="unsupported_algorithm",
            title=exc.title,
            headline=exc.headline,
            details=exc.details,
            as_json=as_json,
        )
        raise SystemExit(2) from exc

    if not decoded.signature:
        fail(
            "signature_missing",
            "Token has an empty signature, so there is nothing to crack",
            "A signature stripped from an HMAC token is an attack shape",
            "Use audit to examine the token structure",
        )
    try:
        signature = base64url_decode(decoded.signature)
    except binascii.Error:
        fail("invalid_base64url", "Token signature is not valid base64url, nothing to crack")

    wordlist_label = str(wordlist)
    if wordlist is None:
        wordlist = bundled_wordlist()
        if wordlist is None:
            fail(
                "wordlist_missing",
                "No wordlist given and the bundled wordlist is missing",
                "Pass a WORDLIST path, or fetch one with: jwt-toolkit download-wordlists",
                title="Invalid Wordlist",
            )
        wordlist_label = f"bundled {BUNDLED_WORDLIST_NAME}"
        status_console.print(f"[dim]Wordlist : {wordlist_label}[/dim]")

    try:
        raw_count = count_lines(wordlist)
    except OSError as exc:
        fail(
            "wordlist_unreadable",
            "Cannot read the wordlist",
            exc.strerror or type(exc).__name__,
            title="Invalid Wordlist",
        )
    if raw_count == 0:
        fail("wordlist_empty", "Wordlist is empty", f"File : {wordlist}", title="Invalid Wordlist")

    total_estimate = raw_count * ENCODING_MULTIPLIER[encoding]
    workers = threads if total_estimate >= MIN_PARALLEL_CANDIDATES else 1
    status_console.print(
        f"[dim]Algorithm : {alg}   "
        f"Candidates : ~{total_estimate:,}   "
        f"Workers : {workers}   "
        f"Encoding : {encoding}[/dim]"
    )

    outcome = _run_crack(
        wordlist,
        wordlist_label=wordlist_label,
        encoding=encoding,
        total_estimate=total_estimate,
        workers=workers,
        alg=alg,
        signing_input=f"{decoded.header_b64}.{decoded.payload_b64}".encode(),
        signature=signature,
    )

    saved: Path | None = None
    save_error: str | None = None
    if outcome.match is not None and output is not None:
        try:
            _save_secret(output, outcome.match.source)
            saved = output
        except OSError as exc:
            save_error = exc.strerror or type(exc).__name__

    if as_json:
        _emit_json(outcome, saved=saved, save_error=save_error)
    elif outcome.match is not None:
        _render_found(outcome, saved=saved, save_error=save_error)
    else:
        _render_not_found(outcome)
    # Found means the token is weak: exit 1 so CI gates fail on it.
    raise SystemExit(1 if outcome.match is not None else 0)


def _run_crack(
    wordlist: Path,
    *,
    wordlist_label: str,
    encoding: str,
    total_estimate: int,
    workers: int,
    alg: str,
    signing_input: bytes,
    signature: bytes,
) -> _Outcome:
    digest = SUPPORTED_ALGORITHMS[alg]().name
    start = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[rate]}[/dim]"),
        TimeElapsedColumn(),
        console=status_console,  # type: ignore[arg-type]  # _ConsoleProxy duck-types Console
        transient=True,
    ) as progress:
        task = progress.add_task("Cracking…", total=total_estimate, rate="-")

        def on_progress(done: int) -> None:
            elapsed = time.perf_counter() - start
            rate = _format_rate(done / elapsed) if elapsed > 0 else "-"
            progress.update(task, completed=done, rate=rate)

        result = find_secret(
            ((candidate, candidate.key) for candidate in iter_candidates(wordlist, encoding)),
            signing_input=signing_input,
            signature=signature,
            digest=digest,
            workers=workers,
            parallel=total_estimate >= MIN_PARALLEL_CANDIDATES,
            on_progress=on_progress,
        )

    return _Outcome(
        alg=alg,
        encoding=encoding,
        wordlist=wordlist_label,
        total_estimate=total_estimate,
        attempts=result.attempts,
        elapsed=time.perf_counter() - start,
        match=result.label,
        position=result.position,
    )


def _save_secret(path: Path, secret: bytes) -> None:
    # The file holds a live credential, so only its owner may read it, even when
    # it already existed with looser permissions.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(secret + b"\n")


def _emit_json(outcome: _Outcome, *, saved: Path | None, save_error: str | None) -> None:
    document: dict[str, object] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "found": outcome.match is not None,
        "algorithm": outcome.alg,
        "wordlist": outcome.wordlist,
        "encoding": outcome.encoding,
        "candidates_tried": outcome.attempts,
        "elapsed_seconds": round(outcome.elapsed, 6),
    }
    if outcome.match is not None and outcome.position is not None:
        document["secret"] = outcome.match.source.decode("utf-8", errors="backslashreplace")
        document["secret_encoding"] = outcome.match.encoding
        document["position"] = outcome.position + 1
        if saved is not None:
            document["saved_to"] = str(saved)
        if save_error is not None:
            document["save_error"] = save_error
    click.echo(json.dumps(document, indent=2))


def _render_found(outcome: _Outcome, *, saved: Path | None, save_error: str | None) -> None:
    assert outcome.match is not None and outcome.position is not None
    saved_line = ""
    if saved is not None:
        saved_line = f"\n[dim]Saved to         : {escape(str(saved))}[/dim]"
    elif save_error is not None:
        saved_line = f"\n[dim yellow]Could not save   : {escape(save_error)}[/dim yellow]"

    console.print(
        Panel(
            f"[bold red]Secret:[/bold red] [bold yellow]{escape(outcome.match.label)}"
            f"[/bold yellow]{saved_line}\n\n"
            f"[dim]Algorithm        : {outcome.alg}[/dim]\n"
            f"[dim]Position         : #{outcome.position + 1:,} of "
            f"~{outcome.total_estimate:,} candidates[/dim]\n"
            f"[dim]Candidates tried : {outcome.attempts:,}[/dim]\n"
            f"[dim]Time elapsed     : {outcome.elapsed:.3f}s[/dim]\n"
            f"[dim]Average rate     : {_format_rate(outcome.rate)}[/dim]\n\n"
            "[bold red]This secret is in the wordlist, so it is not safe.[/bold red]\n"
            "[dim]Generate a strong secret with: jwt-toolkit generate-secret[/dim]",
            title="[bold red]Weak Secret Detected[/bold red]",
            border_style="red",
        )
    )


def _render_not_found(outcome: _Outcome) -> None:
    console.print(
        Panel(
            "[bold green]Secret not found in this wordlist[/bold green]\n\n"
            f"[dim]Algorithm        : {outcome.alg}[/dim]\n"
            f"[dim]Candidates tried : {outcome.attempts:,}[/dim]\n"
            f"[dim]Time elapsed     : {outcome.elapsed:.3f}s[/dim]\n"
            f"[dim]Average rate     : {_format_rate(outcome.rate)}[/dim]\n\n"
            "[dim]This does not prove the secret is strong: a larger wordlist[/dim]\n"
            "[dim]may still find it. Use jwt-toolkit generate-secret if you need[/dim]\n"
            "[dim]a cryptographically strong secret.[/dim]",
            title="[bold green]Wordlist Check Passed[/bold green]",
            border_style="green",
        )
    )
