import base64
import binascii
import json
import math
import threading
import time
import hmac as _hmac
import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from jwt_toolkit.core.crypto import SUPPORTED_ALGORITHMS, base64url_encode
from jwt_toolkit.core.decoder import decode_token, split_token

# Crack command — brute-forces a weak HMAC JWT secret against a wordlist.

console = Console()

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
                padded = c + "=" * (-len(c) % 4)
                result.append((f"{c} [b64]", base64.b64decode(padded)))
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
    # Brute-force a weak HMAC JWT secret using a wordlist.
    try:
        header, _, signature = decode_token(token)
        header_b64, payload_b64, _ = split_token(token)
        alg = header.get("alg", "").upper()

        if not signature:
            console.print(Panel(
                "[bold red]Token has an empty signature — nothing to crack[/bold red]\n\n"
                "[dim]An empty signature is characteristic of an alg:none attack[/dim]\n"
                "[dim]Use inspect to examine the token structure[/dim]",
                title="Cannot Crack",
                border_style="red",
            ))
            raise SystemExit(2)

        if alg == "NONE":
            console.print(Panel(
                "[bold red]Token uses alg: none — there is no signature to crack[/bold red]\n\n"
                "[dim]An unsigned token can be forged without any secret[/dim]",
                title="Cannot Crack",
                border_style="red",
            ))
            raise SystemExit(2)

        if alg not in SUPPORTED_ALGORITHMS:
            console.print(Panel(
                f"[bold red]Unsupported algorithm: {alg}[/bold red]\n\n"
                f"[dim]crack only works on HMAC tokens: {', '.join(SUPPORTED_ALGORITHMS)}[/dim]",
                title="Cannot Crack",
                border_style="red",
            ))
            raise SystemExit(2)

        with open(wordlist, "r", errors="ignore") as f:
            raw = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not raw:
            console.print(Panel(
                "[bold red]Wordlist is empty[/bold red]\n\n"
                f"[dim]File : {wordlist}[/dim]",
                title="Invalid Wordlist",
                border_style="red",
            ))
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

        # Pre-compute signing invariants outside the hot loop.
        digestmod = SUPPORTED_ALGORITHMS[alg]
        signing_input = f"{header_b64}.{payload_b64}".encode()

        def _check(sbytes: bytes) -> bool:
            digest = _hmac.new(sbytes, signing_input, digestmod).digest()
            return _hmac.compare_digest(base64url_encode(digest), signature)

        # Shared state
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

        # Launch workers in chunks to keep it simple, no need for a queue here.
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
            result = found_box[0]
            final_attempts = attempts_box[0]

        avg_rate = final_attempts / elapsed if elapsed > 0 else 0

        if result is not None:
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
            raise SystemExit(1)
        else:
            # Not cracked = good: secret is not in this wordlist.
            console.print(Panel(
                "[bold green]Secret not found in this wordlist[/bold green]\n\n"
                f"[dim]Algorithm        : {alg}[/dim]\n"
                f"[dim]Candidates tried : {final_attempts:,}[/dim]\n"
                f"[dim]Time elapsed     : {elapsed:.3f}s[/dim]\n"
                f"[dim]Average rate     : {_format_rate(avg_rate)}[/dim]\n\n"
                "[dim]This does not guarantee the secret is strong — a larger[/dim]\n"
                "[dim]wordlist may still find it. Use jwt-toolkit generate-secret[/dim]\n"
                "[dim]if you need a cryptographically strong secret.[/dim]",
                title="[bold green]Wordlist Check Passed[/bold green]",
                border_style="green",
            ))

    except binascii.Error:
        console.print(Panel(
            "[bold red]Token contains invalid base64url encoding[/bold red]\n\n"
            "[dim]One or more parts could not be decoded[/dim]\n"
            "[dim]The token may be truncated or corrupted[/dim]",
            title="Decode Error",
            border_style="red",
        ))
        raise SystemExit(2)

    except json.JSONDecodeError as e:
        console.print(Panel(
            "[bold red]Token decoded but header or payload is not valid JSON[/bold red]\n\n"
            f"[dim]JSON error : {e.msg}[/dim]\n"
            "[dim]The token structure may be corrupted[/dim]",
            title="Parse Error",
            border_style="red",
        ))
        raise SystemExit(2)

    except ValueError as e:
        console.print(Panel(
            f"[bold red]{e}[/bold red]\n\n"
            "[dim]A JWT must have exactly 3 base64url parts separated by dots[/dim]\n"
            "[dim]Format : <header>.<payload>.<signature>[/dim]",
            title="Invalid Token",
            border_style="red",
        ))
        raise SystemExit(2)
