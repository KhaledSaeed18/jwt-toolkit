import hmac as _hmac
import os
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
from jwt_toolkit.cli.decoding import render_algorithm_error, resolve_token, safe_decode
from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS
from jwt_toolkit.core.encoding import base64_decode_padded, base64url_encode
from jwt_toolkit.core.errors import UnsupportedAlgorithmError

# Crack command — brute-forces a weak HMAC JWT secret against a wordlist.

# Items pulled from the generator per lock acquisition — reduces contention
# on the hot loop without buffering the whole file in memory.
_BATCH_SIZE = 200

# Expansion factor used to estimate total candidates before streaming starts.
_ENCODING_MULTIPLIER = {"utf-8": 1, "hex": 1, "base64": 1, "all": 3}

_DEFAULT_THREADS = min(os.cpu_count() or 4, 8)


def _iter_candidates(wordlist_path: str, encoding: str):
    """Stream (label, secret_bytes) pairs from a wordlist file.

    Handles P2 (no full-file load) and P3 (dedup by bytes) in one pass.
    """
    seen: set[bytes] = set()
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            if encoding in ("utf-8", "all"):
                sbytes = word.encode("utf-8", errors="replace")
                if sbytes not in seen:
                    seen.add(sbytes)
                    yield word, sbytes
            if encoding in ("hex", "all"):
                try:
                    sbytes = bytes.fromhex(word)
                    if sbytes not in seen:
                        seen.add(sbytes)
                        yield f"{word} [hex]", sbytes
                except ValueError:
                    pass
            if encoding in ("base64", "all"):
                try:
                    sbytes = base64_decode_padded(word)
                    if sbytes not in seen:
                        seen.add(sbytes)
                        yield f"{word} [b64]", sbytes
                except Exception:
                    pass


def _count_raw_lines(wordlist_path: str) -> int:
    """Fast pre-scan: count valid (non-empty, non-comment) lines."""
    count = 0
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                count += 1
    return count


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
    default=_DEFAULT_THREADS,
    show_default=True,
    type=click.IntRange(1, 64),
    help="Worker threads (1–64)",
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

    raw_count = _count_raw_lines(wordlist)
    if raw_count == 0:
        print_error(
            "Wordlist is empty",
            f"File : {wordlist}",
            title="Invalid Wordlist",
        )
        raise SystemExit(2)

    total_estimate = raw_count * _ENCODING_MULTIPLIER.get(encoding, 1)

    if not os.environ.get("JWT_TOOLKIT_QUIET"):
        console.print(
            f"[dim]Algorithm : {alg}   "
            f"Candidates : ~{total_estimate:,}   "
            f"Threads : {threads}   "
            f"Encoding : {encoding}[/dim]"
        )

    result, final_attempts, elapsed = _run_crack(
        wordlist, encoding, total_estimate, threads, alg,
        decoded.header_b64, decoded.payload_b64, decoded.signature,
    )
    avg_rate = final_attempts / elapsed if elapsed > 0 else 0

    if result is not None:
        _render_found(result, alg, total_estimate, elapsed, avg_rate, output)
        raise SystemExit(1)
    _render_not_found(alg, final_attempts, elapsed, avg_rate)


def _run_crack(
    wordlist_path: str,
    encoding: str,
    total_estimate: int,
    threads: int,
    alg: str,
    header_b64: str,
    payload_b64: str,
    signature: str,
) -> tuple[tuple[str, int] | None, int, float]:
    digestmod = SUPPORTED_ALGORITHMS[alg]
    signing_input = f"{header_b64}.{payload_b64}".encode()

    def _check(sbytes: bytes) -> bool:
        digest = _hmac.new(sbytes, signing_input, digestmod).digest()
        # compare_digest avoids leaking signature length via short-circuit.
        return _hmac.compare_digest(base64url_encode(digest), signature)

    gen = _iter_candidates(wordlist_path, encoding)
    gen_lock = threading.Lock()
    position_counter: list[int] = [0]
    stop_event = threading.Event()
    lock = threading.Lock()
    found_box: list[tuple[str, int] | None] = [None]
    attempts_box: list[int] = [0]

    def worker() -> None:
        local_attempts = 0
        while not stop_event.is_set():
            # Pull a batch under a single lock acquisition to keep contention low.
            with gen_lock:
                batch: list[tuple[int, tuple[str, bytes]]] = []
                for _ in range(_BATCH_SIZE):
                    item = next(gen, None)
                    if item is None:
                        break
                    pos = position_counter[0]
                    position_counter[0] += 1
                    batch.append((pos, item))  # type: ignore[arg-type]
            if not batch:
                break
            for pos, (label, sbytes) in batch:
                if stop_event.is_set():
                    break
                if _check(sbytes):
                    with lock:
                        found_box[0] = (label, pos)
                    stop_event.set()
                    break
                local_attempts += 1
                if local_attempts % 500 == 0:
                    with lock:
                        attempts_box[0] += local_attempts
                    local_attempts = 0
        with lock:
            attempts_box[0] += local_attempts

    thread_list = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(threads)
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
        task = progress.add_task("Cracking…", total=total_estimate, rate="–")

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
    total_estimate: int,
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
        f"[dim]Position         : #{idx + 1} of ~{total_estimate:,} candidates[/dim]\n"
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
