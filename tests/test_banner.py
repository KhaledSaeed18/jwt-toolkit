import io
import random

import pytest
from rich.console import Console

from jwt_toolkit import __version__
from jwt_toolkit.cli import banner
from jwt_toolkit.cli.banner_art import ART_NARROW, ART_WIDE


def _recording_console(width: int = 120) -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, width=width, color_system=None, force_terminal=False), buffer


def _widest(art: tuple[str, ...]) -> int:
    return max(len(line) for line in art)


def test_pre_rendered_art_has_no_trailing_whitespace() -> None:
    for art in (*ART_WIDE, *ART_NARROW):
        assert art
        assert all(line == line.rstrip() for line in art)


def test_pick_art_uses_wide_fonts_on_a_wide_terminal() -> None:
    assert banner._pick_art(200, random.Random(1)) in ART_WIDE


def test_pick_art_uses_narrow_fonts_on_a_narrow_terminal() -> None:
    assert banner._pick_art(60, random.Random(1)) in ART_NARROW


@pytest.mark.parametrize("width", [40, 60, 78, 85, 100])
def test_pick_art_always_fits_the_terminal(width: int) -> None:
    for seed in range(10):
        assert _widest(banner._pick_art(width, random.Random(seed))) <= width


def test_pick_art_falls_back_to_plain_art_when_nothing_fits() -> None:
    art = banner._pick_art(10, random.Random(1))
    assert art == tuple(banner._PLAIN_FALLBACK.strip("\n").splitlines())


def test_pad_gives_every_line_the_same_width() -> None:
    padded = banner._pad(("ab", "abcd", ""))
    assert padded == ["ab  ", "abcd", "    "]


def test_render_banner_shows_title_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(banner, "_terminal_width", lambda default=80: 120)
    console, buffer = _recording_console()
    banner.render_banner(console=console, animate=False)
    output = buffer.getvalue()
    assert "JWT Security Toolkit" in output
    assert f"v{__version__}" in output
    assert "\x1b[" not in output


def test_render_help_lists_every_command() -> None:
    console, buffer = _recording_console()
    banner.render_help(console=console)
    output = buffer.getvalue()
    for name, _ in banner.COMMANDS:
        assert name in output


@pytest.mark.parametrize(
    ("env", "tty", "expected"),
    [
        ({}, True, True),
        ({}, False, False),
        ({"CI": "1"}, True, False),
        ({"NO_COLOR": "1"}, True, False),
        ({"TERM": "dumb"}, True, False),
    ],
)
def test_animation_only_runs_in_an_interactive_terminal(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], tty: bool, expected: bool
) -> None:
    for name in ("CI", "NO_COLOR", "TERM"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(banner.sys.stdout, "isatty", lambda: tty)
    assert banner._is_animation_safe() is expected
