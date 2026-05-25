import hmac as _hmac
import math
import threading
import time

import click
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
from jwt_toolkit.cli.decoding import render_algorithm_error, safe_decode
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS
from jwt_toolkit.core.encoding import base64_decode_padded, base64url_encode
from jwt_toolkit.core.errors import UnsupportedAlgorithmError

# Crack command — brute-forces a weak HMAC JWT secret against a wordlist.


def _expand_candidates(raw: list[str], encoding: str) -> list[tuple[str, bytes]]:
    # Return (display_label, secret_bytes) pairs expanded by the chosen encoding mode.
    result: list[tuple[str, bytes]] = []
    for c in raw:
        if encoding in ("utf-8", "all"):
            result.append((c, c.encode("utf-8", errors="replace")))
        if encoding in ("hex", "all"):
            try:
                result.append((f"{c} [hex]", bytes.fromhex(c)))
            except ValueError:
                pass
        if encoding in ("base64", "all"):
            try:
                result.append((f"{c} [b64]", base64_decode_padded(c)))
            except Exception:
                pass
    return result


def _format_rate(rate: float) -> str:
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.1f}M c/s"
    if rate >= 1_000:
        return f"{rate / 1_000:.1f}k c/s"
    return f"{rate:.0f} c/s"


@click.command(help="Brute-force a weak HMAC JWT secret using a wordlist.")
@click.argument("token")
@click.argument("wordlist", type=click.Path(exists=True, readable=True))
@click.option(
    "--threads",
    default=4,
    show_default=True,
    type=click.IntRange(1, 16),
    help="Worker threads (1–16)",
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
def crack(token: str, wordlist: str, threads: int, encoding: str, output: str | None):
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

    with open(wordlist, "r", errors="ignore") as f:
        raw = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not raw:
        print_error(
            "Wordlist is empty",
            f"File : {wordlist}",
            title="Invalid Wordlist",
        )
        raise SystemExit(2)

    expanded = _expand_candidates(raw, encoding)
    total = len(expanded)
    threads = min(threads, total)

    console.print(
        f"[dim]Algorithm : {alg}   "
        f"Candidates : {total:,}   "
        f"Threads : {threads}   "
        f"Encoding : {encoding}[/dim]"
    )

    result, final_attempts, elapsed = _run_crack(
        expanded, threads, alg, decoded.header_b64, decoded.payload_b64, decoded.signature
    )
    avg_rate = final_attempts / elapsed if elapsed > 0 else 0

    if result is not None:
        _render_found(result, alg, total, elapsed, avg_rate, output)
        raise SystemExit(1)
    _render_not_found(alg, final_attempts, elapsed, avg_rate)


def _run_crack(
    expanded: list[tuple[str, bytes]],
    threads: int,
    alg: str,
    header_b64: str,
    payload_b64: str,
    signature: str,
) -> tuple[tuple[str, int] | None, int, float]:
    # Pre-compute signing invariants outside the hot loop.
    digestmod = SUPPORTED_ALGORITHMS[alg]
    signing_input = f"{header_b64}.{payload_b64}".encode()

    def _check(sbytes: bytes) -> bool:
        digest = _hmac.new(sbytes, signing_input, digestmod).digest()
        # compare_digest avoids leaking signature length via short-circuit.
        return _hmac.compare_digest(base64url_encode(digest), signature)

    stop_event = threading.Event()
    lock = threading.Lock()
    found_box: list[tuple[str, int] | None] = [None]
    attempts_box: list[int] = [0]

    def worker(chunk: list[tuple[str, bytes]], offset: int) -> None:
        local = 0
        for i, (label, sbytes) in enumerate(chunk):
            if stop_event.is_set():
                break
            if _check(sbytes):
                with lock:
                    found_box[0] = (label, offset + i)
                stop_event.set()
                return
            local += 1
            # Flush local counter in batches to keep lock contention low.
            if local % 100 == 0:
                with lock:
                    attempts_box[0] += local
                local = 0
        with lock:
            attempts_box[0] += local

    total = len(expanded)
    chunk_size = math.ceil(total / threads)
    thread_list = [
        threading.Thread(
            target=worker,
            args=(expanded[i : i + chunk_size], i),
            daemon=True,
        )
        for i in range(0, total, chunk_size)
    ]

    start = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[rate]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Cracking…", total=total, rate="–")

        for t in thread_list:
            t.start()

        prev_attempts = 0
        prev_time = start

        # Poll workers every 150ms; refresh rate display every 400ms.
        while not stop_event.is_set() and any(t.is_alive() for t in thread_list):
            time.sleep(0.15)
            with lock:
                done = attempts_box[0]

            now = time.perf_counter()
            dt = now - prev_time
            if dt >= 0.4:
                rate = (done - prev_attempts) / dt
                progress.update(task, completed=done, rate=_format_rate(rate))
                prev_attempts = done
                prev_time = now
            else:
                progress.update(task, completed=done)

        for t in thread_list:
            t.join()

    elapsed = time.perf_counter() - start
    with lock:
        return found_box[0], attempts_box[0], elapsed


def _render_found(
    result: tuple[str, int],
    alg: str,
    total: int,
    elapsed: float,
    avg_rate: float,
    output: str | None,
) -> None:
    label, idx = result
    saved_line = ""
    if output:
        try:
            with open(output, "w") as fout:
                fout.write(label + "\n")
            saved_line = f"\n[dim]Saved to         : {output}[/dim]"
        except OSError as exc:
            saved_line = f"\n[dim yellow]Could not save: {exc}[/dim yellow]"

    # Cracked = bad: the secret is dangerously weak.
    console.print(Panel(
        f"[bold red]Secret:[/bold red] [bold yellow]{label}[/bold yellow]{saved_line}\n\n"
        f"[dim]Algorithm        : {alg}[/dim]\n"
        f"[dim]Position         : #{idx + 1} of {total:,} candidates[/dim]\n"
        f"[dim]Candidates tried : {idx + 1:,}[/dim]\n"
        f"[dim]Time elapsed     : {elapsed:.3f}s[/dim]\n"
        f"[dim]Average rate     : {_format_rate(avg_rate)}[/dim]\n\n"
        "[bold red]This secret is in a common wordlist — it is not safe.[/bold red]\n"
        "[dim]Generate a strong secret with: jwt-toolkit generate-secret[/dim]",
        title="[bold red]Weak Secret Detected[/bold red]",
        border_style="red",
    ))


def _render_not_found(alg: str, attempts: int, elapsed: float, avg_rate: float) -> None:
    console.print(Panel(
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
    ))
