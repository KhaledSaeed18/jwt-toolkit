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

from jwt_toolkit.cli.banner_art import ART_NARROW, ART_WIDE
from jwt_toolkit.cli.console import console as _shared_console

# The banner is intentionally only shown for the bare invocation. Printing it
# for every subcommand would corrupt --json output and pollute Click's usage
# errors, so subcommands stay clean.


def _get_version() -> str:
    try:
        return version("jwt-toolkit")
    except PackageNotFoundError:
        return "0.0.0"


# Cool cyan→violet gradient applied line-by-line to the ASCII art.
_GRADIENT = ("#22d3ee", "#06b6d4", "#3b82f6", "#6366f1", "#8b5cf6")

_ACCENT = "bright_cyan"
_DIM = "grey50"

_SUBTITLE = "JWT Security Toolkit"
_TAGLINE = "Decode · Sign · Audit · Verify · Forge · Crack · Generate"
_REPO_URL = "https://github.com/KhaledSaeed18/jwt-toolkit"

# Shown when every pre-rendered font is wider than the terminal.
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


def _pick_art(width: int, rng: random.Random | None = None) -> tuple[str, ...]:
    """Pick a random pre-rendered title that fits ``width`` columns."""
    candidates = list(ART_WIDE if width >= 78 else ART_NARROW)
    (rng or random.Random()).shuffle(candidates)
    for art in candidates:
        if max((len(line) for line in art), default=0) <= width:
            return art
    return tuple(_PLAIN_FALLBACK.strip("\n").splitlines())


def _pad(art: tuple[str, ...]) -> list[str]:
    # Every line shares one width so centering keeps the letters aligned.
    widest = max((len(line) for line in art), default=0)
    return [line.ljust(widest) for line in art]


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
    out = console if console is not None else _shared_console
    if animate is None:
        animate = _is_animation_safe()

    width = _terminal_width()
    lines = _pad(_pick_art(width))
    total = len(lines)

    # Top breathing room
    out.print()

    for i, line in enumerate(lines):
        out.print(Align.center(_colorize_line(line, i, total)))
        if animate:
            time.sleep(0.012)

    out.print()
    out.print(Align.center(Text(_SUBTITLE, style=f"bold {_ACCENT}")))
    out.print(Align.center(Text(_TAGLINE, style=_DIM)))

    divider_width = min(max(width - 8, 20), 60)
    out.print(Align.center(Text("─" * divider_width, style=_DIM)))
    out.print(Align.center(_info_line(_get_version())))
    out.print()


# Single source for the command list and examples; CLI_HELP is built from these too.
COMMANDS: tuple[tuple[str, str], ...] = (
    ("decode", "Decode a JWT and pretty-print its header and payload."),
    ("sign", "Mint a new JWT signed with an HMAC secret or a private key."),
    ("audit", "Static security analysis of a JWT (no key required)."),
    ("verify", "Verify the signature and standard claims of a JWT."),
    ("diff", "Compare two JWTs and show which fields changed."),
    ("forge", "Emit defensive attack-shaped variants of a JWT for self-audit."),
    ("crack", "Brute-force a weak HMAC secret using a wordlist."),
    ("generate-secret", "Emit a cryptographically strong random secret."),
    ("download-wordlists", "Fetch the common-secrets wordlist for this release."),
)

EXAMPLES: tuple[tuple[str, str], ...] = (
    ("decode a token", "jwt-toolkit decode <token>"),
    ("mint a token", 'jwt-toolkit sign --payload \'{"sub":"1"}\' --secret-file hs256.secret'),
    ("mint with a private key", 'jwt-toolkit sign --payload \'{"sub":"1"}\' --private-key key.pem'),
    ("audit a token", "jwt-toolkit audit <token>"),
    ("strict JSON report", "jwt-toolkit audit <token> --strict --json"),
    (
        "verify signature and claims",
        "jwt-toolkit verify <token> --secret-file hs256.secret --issuer auth.example.com",
    ),
    (
        "verify against a JWKS",
        "jwt-toolkit verify <token> --jwks-url https://auth.example/.well-known/jwks.json",
    ),
    ("compare two tokens", "jwt-toolkit diff @before.jwt @after.jwt"),
    ("forge defensive test cases", "jwt-toolkit forge <token> --public-key key.pub.pem"),
    ("test for a weak secret", "jwt-toolkit crack <token>"),
    ("use a larger wordlist", "jwt-toolkit crack <token> rockyou.txt --workers 4"),
    ("generate a 256-bit secret", "jwt-toolkit generate-secret --bits 256 --encoding base64"),
    ("fetch the wordlist", "jwt-toolkit download-wordlists --output-dir wordlists"),
)

_OPTIONS: tuple[tuple[str, str], ...] = (
    ("--version", "Show the version and exit."),
    ("--no-banner", "Suppress the startup banner (env: JWT_TOOLKIT_NO_BANNER)."),
    ("--quiet", "Keep results and errors, drop progress and hints (env: JWT_TOOLKIT_QUIET)."),
    ("--no-color", "Disable color output (env: NO_COLOR)."),
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
    out = console if console is not None else _shared_console

    about = Text(
        "A command-line toolkit for inspecting, verifying, cracking, and securing "
        "JSON Web Tokens, built to expose how JWT signing works and where it breaks.",
        style="white",
    )
    out.print(_section_header("ABOUT"))
    out.print(Padding(about, (0, 4, 1, 4)))

    usage = Text()
    usage.append("$ ", style=_DIM)
    usage.append("jwt-toolkit ", style="bold white")
    usage.append("[OPTIONS] ", style=_ACCENT)
    usage.append("COMMAND ", style="bold magenta")
    usage.append("[ARGS]...", style=_DIM)

    out.print(_section_header("USAGE"))
    out.print(Padding(usage, (0, 0, 1, 4)))

    out.print(_section_header("COMMANDS"))
    out.print(
        Padding(
            _two_col_table(COMMANDS, key_style="bold cyan"),
            (0, 0, 1, 2),
        )
    )

    out.print(_section_header("EXAMPLES"))
    out.print(
        Padding(
            _two_col_table(EXAMPLES, key_style=_DIM, value_style="bright_green", key_prefix="# "),
            (0, 0, 1, 2),
        )
    )

    out.print(_section_header("OPTIONS"))
    out.print(
        Padding(
            _two_col_table(_OPTIONS, key_style="yellow"),
            (0, 0, 1, 2),
        )
    )

    hint = Text("Run ", style=_DIM)
    hint.append("jwt-toolkit COMMAND --help", style=f"bold {_ACCENT}")
    hint.append(" for command-specific options.", style=_DIM)
    out.print(Padding(hint, (0, 0, 0, 2)))
    out.print()
