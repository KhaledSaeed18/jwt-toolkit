from __future__ import annotations

import os
import random
import shutil
import sys
import time
from importlib.metadata import PackageNotFoundError, version

from rich.align import Align
from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

try:
    from pyfiglet import Figlet, FontNotFound  # type: ignore

    _HAS_FIGLET = True
except ImportError:
    _HAS_FIGLET = False

from jwt_toolkit.cli.console import console as _shared_console

# Banner — startup splash for `jwt-toolkit` with no subcommand.
# The banner is intentionally only shown for the bare invocation. Printing it
# for every subcommand would corrupt --json output and pollute Click's usage
# errors, so subcommands stay clean.


def _get_version() -> str:
    try:
        return version("jwt-toolkit")
    except PackageNotFoundError:
        return "0.0.0"


# Three figlet fonts at full width, plus narrower fallbacks for small terminals.
# One is picked at random each invocation so the splash doesn't feel static.
_FONTS_WIDE = ("slant", "ansi_shadow", "small_slant")
_FONTS_NARROW = ("small", "standard", "mini")

# Cool cyan→violet gradient applied line-by-line to the ASCII art.
_GRADIENT = ("#22d3ee", "#06b6d4", "#3b82f6", "#6366f1", "#8b5cf6")

_ACCENT = "bright_cyan"
_DIM = "grey50"

_SUBTITLE = "JWT Security Toolkit"
_TAGLINE = "Decode · Sign · Audit · Verify · Forge · Crack · Generate"
_REPO_URL = "https://github.com/KhaledSaeed18/jwt-toolkit"

# Plain-ASCII fallback shown when pyfiglet is unavailable or every font is
# wider than the terminal. Kept narrow on purpose (~60 cols).
_PLAIN_FALLBACK = r"""
   _ _    _ _____   _____           _ _    _ _
  | | |  | |_   _| |_   _|__   ___ | | | _(_) |_
  | | |/\| | | |     | |/ _ \ / _ \| | |/ / | __|
 _/ |   /\   | |     | | (_) | (_) | |   <| | |_
|__/|__/  \__|_|     |_|\___/ \___/|_|_|\_\_|\__|
"""


def _is_animation_safe() -> bool:
    """Disable animation in non-interactive contexts (pipes, CI, NO_COLOR)."""
    if not sys.stdout.isatty():
        return False
    if os.environ.get("CI"):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return os.environ.get("TERM") != "dumb"


def _terminal_width(default: int = 80) -> int:
    return shutil.get_terminal_size((default, 20)).columns


def _pick_art(width: int) -> tuple[str, bool]:
    """Render the title via pyfiglet; return (art, used_figlet)."""
    if not _HAS_FIGLET:
        return _PLAIN_FALLBACK.strip("\n"), False

    fonts = _FONTS_WIDE if width >= 78 else _FONTS_NARROW
    candidates = list(fonts)
    random.shuffle(candidates)

    for font in candidates:
        try:
            fig = Figlet(font=font, width=max(width, 40))
            art = fig.renderText("JWT Toolkit").rstrip("\n")
        except (FontNotFound, Exception):
            continue
        max_line = max((len(line) for line in art.splitlines()), default=0)
        if max_line <= width:
            return art, True

    return _PLAIN_FALLBACK.strip("\n"), False


def _colorize_line(line: str, line_index: int, total_lines: int) -> Text:
    idx = 0 if total_lines <= 1 else int((line_index / (total_lines - 1)) * (len(_GRADIENT) - 1))
    return Text(line, style=_GRADIENT[idx])


def _info_line(ver: str) -> Text:
    line = Text()
    line.append("v", style=_DIM)
    line.append(ver, style=_ACCENT)
    line.append("  ·  ", style=_DIM)
    line.append("python ", style=_DIM)
    line.append(f"{sys.version_info.major}.{sys.version_info.minor}", style=_ACCENT)
    line.append("  ·  ", style=_DIM)
    line.append(_REPO_URL, style=f"underline {_DIM}")
    return line


def render_banner(
    *,
    console: Console | None = None,
    animate: bool | None = None,
) -> None:
    """Render the startup banner.

    The banner reveals line-by-line in a fast (~120ms) cascade when running in
    an interactive terminal, and falls back to a single-shot render in pipes,
    CI, or when NO_COLOR / TERM=dumb is set.
    """
    console = console or _shared_console
    if animate is None:
        animate = _is_animation_safe()

    width = _terminal_width()
    art, _ = _pick_art(width)
    lines = art.splitlines()
    total = len(lines)

    # Top breathing room
    console.print()

    for i, line in enumerate(lines):
        console.print(Align.center(_colorize_line(line, i, total)))
        if animate:
            time.sleep(0.012)

    console.print()
    console.print(Align.center(Text(_SUBTITLE, style=f"bold {_ACCENT}")))
    console.print(Align.center(Text(_TAGLINE, style=_DIM)))

    divider_width = min(max(width - 8, 20), 60)
    console.print(Align.center(Text("─" * divider_width, style=_DIM)))
    console.print(Align.center(_info_line(_get_version())))
    console.print()


# help layout
_COMMANDS: tuple[tuple[str, str], ...] = (
    ("decode", "Decode a JWT and pretty-print its header and payload."),
    ("sign", "Mint a new JWT from a payload and HMAC or asymmetric key."),
    ("audit", "Static security analysis of a JWT — no key required."),
    ("verify", "Verify a JWT's signature and standard claims."),
    ("forge", "Emit defensive attack-shaped variants of a JWT for self-audit."),
    ("crack", "Brute-force a weak HMAC secret using a wordlist."),
    ("generate-secret", "Emit a cryptographically strong random secret."),
    ("download-wordlists", "Fetch the latest common-secrets wordlist."),
)

_EXAMPLES: tuple[tuple[str, str], ...] = (
    ("decode a token", "jwt-toolkit decode <token>"),
    ("mint a new token", 'jwt-toolkit sign --payload \'{"sub":"1"}\' --secret <secret>'),
    ("audit a token", "jwt-toolkit audit <token>"),
    ("strict + JSON report", "jwt-toolkit audit <token> --strict --json"),
    (
        "verify signature & claims",
        "jwt-toolkit verify <token> --secret <secret> --issuer auth.example.com",
    ),
    (
        "verify against a JWKS",
        "jwt-toolkit verify <token> --jwks-url https://auth.example/.well-known/jwks.json",
    ),
    (
        "forge defensive test cases",
        "jwt-toolkit forge <token> --public-key key.pub.pem",
    ),
    (
        "crack a weak HMAC secret",
        "jwt-toolkit crack <token> wordlists/common-secrets.txt --threads 8",
    ),
    ("generate a 256-bit secret", "jwt-toolkit generate-secret --bits 256 --encoding base64"),
    ("refresh the wordlist", "jwt-toolkit download-wordlists --output-dir wordlists"),
)

_OPTIONS: tuple[tuple[str, str], ...] = (
    ("--version", "Show the version and exit."),
    ("--no-banner", "Suppress the startup banner  (env: JWT_TOOLKIT_NO_BANNER)."),
    ("-h, --help", "Show this message and exit."),
)


def _section_header(title: str) -> Text:
    header = Text()
    header.append("▌ ", style=f"bold {_ACCENT}")
    header.append(title, style=f"bold {_ACCENT}")
    return header


def _two_col_table(
    rows: tuple[tuple[str, str], ...],
    *,
    key_style: str,
    value_style: str = "white",
    key_prefix: str = "",
) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 3), pad_edge=False)
    table.add_column(style=key_style, no_wrap=True)
    table.add_column(style=value_style, overflow="fold")
    for key, value in rows:
        table.add_row(f"{key_prefix}{key}", value)
    return table


def render_help(console: Console | None = None) -> None:
    """Render a polished, sectioned help screen for the bare invocation."""
    console = console or _shared_console

    # ABOUT
    about = Text(
        "A command-line toolkit for inspecting, verifying, cracking, and securing "
        "JSON Web Tokens — built to expose how JWT signing works and where it breaks.",
        style="white",
    )
    console.print(_section_header("ABOUT"))
    console.print(Padding(about, (0, 4, 1, 4)))

    # USAGE
    usage = Text()
    usage.append("$ ", style=_DIM)
    usage.append("jwt-toolkit ", style="bold white")
    usage.append("[OPTIONS] ", style=_ACCENT)
    usage.append("COMMAND ", style="bold magenta")
    usage.append("[ARGS]...", style=_DIM)

    console.print(_section_header("USAGE"))
    console.print(Padding(usage, (0, 0, 1, 4)))

    # COMMANDS
    console.print(_section_header("COMMANDS"))
    console.print(
        Padding(
            _two_col_table(_COMMANDS, key_style="bold cyan"),
            (0, 0, 1, 2),
        )
    )

    # EXAMPLES — dim "# label" comment beside a green command line
    console.print(_section_header("EXAMPLES"))
    console.print(
        Padding(
            _two_col_table(_EXAMPLES, key_style=_DIM, value_style="bright_green", key_prefix="# "),
            (0, 0, 1, 2),
        )
    )

    # OPTIONS
    console.print(_section_header("OPTIONS"))
    console.print(
        Padding(
            _two_col_table(_OPTIONS, key_style="yellow"),
            (0, 0, 1, 2),
        )
    )

    hint = Text("Run ", style=_DIM)
    hint.append("jwt-toolkit COMMAND --help", style=f"bold {_ACCENT}")
    hint.append(" for command-specific options.", style=_DIM)
    console.print(Padding(hint, (0, 0, 0, 2)))
    console.print()
