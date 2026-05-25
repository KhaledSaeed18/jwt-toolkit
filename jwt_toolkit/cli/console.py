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

    # Rich internals (Live, Progress) use the console as a context manager.
    # Python looks up dunder methods on the type, not the instance, so
    # __getattr__ alone is not enough — we must forward them explicitly.
    def __enter__(self):
        return self._get().__enter__()

    def __exit__(self, *args):
        return self._get().__exit__(*args)


console = _ConsoleProxy()
