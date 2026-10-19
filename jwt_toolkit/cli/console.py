import os
from typing import Any

from rich.console import Console


def is_quiet() -> bool:
    return bool(os.environ.get("JWT_TOOLKIT_QUIET"))


class _ConsoleProxy:
    """Lazy console that follows --no-color and --quiet, which the root command sets in the environment."""

    def __init__(self, *, stderr: bool = False, mute_when_quiet: bool = False) -> None:
        self._stderr = stderr
        self._mute_when_quiet = mute_when_quiet
        self._inner: Console | None = None
        self._settings: tuple[bool, bool] | None = None

    def _get(self) -> Console:
        # Rebuilt when the settings change, so a process that runs several commands
        # (or a test suite) never keeps a console configured for an earlier one.
        settings = (bool(os.environ.get("NO_COLOR")), self._mute_when_quiet and is_quiet())
        if self._inner is None or settings != self._settings:
            self._inner = Console(stderr=self._stderr, no_color=settings[0], quiet=settings[1])
            self._settings = settings
        return self._inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)

    # Rich internals (Live, Progress) use the console as a context manager, and
    # Python looks dunder methods up on the type, so they are forwarded explicitly.
    def __enter__(self) -> Console:
        return self._get().__enter__()

    def __exit__(self, *args: Any) -> None:
        return self._get().__exit__(*args)


# Results: what the command was run for. Never muted, so --quiet keeps them.
console = _ConsoleProxy()
# Errors go to stderr so a redirected result (`sign ... > token.jwt`) never captures them.
err_console = _ConsoleProxy(stderr=True)
# Progress, hints, and context lines: the non-essential output --quiet removes. On
# stderr so it never mixes into a result that is piped or parsed, such as --json.
status_console = _ConsoleProxy(stderr=True, mute_when_quiet=True)
