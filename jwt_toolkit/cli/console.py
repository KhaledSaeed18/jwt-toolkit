from __future__ import annotations

import os

from rich.console import Console


class _ConsoleProxy:
    """Lazy proxy so --no-color and --quiet env vars are set before Console is created."""

    def __init__(self) -> None:
        self._inner: Console | None = None

    def _get(self) -> Console:
        if self._inner is None:
            self._inner = Console(
                no_color=bool(os.environ.get("NO_COLOR")),
                quiet=bool(os.environ.get("JWT_TOOLKIT_QUIET")),
            )
        return self._inner

    def __getattr__(self, name: str):
        return getattr(self._get(), name)


console = _ConsoleProxy()
