from collections.abc import Iterable

from rich.markup import escape
from rich.panel import Panel

from jwt_toolkit.cli.console import console, err_console


# Headlines and details are plain text and may carry token or user input, so they are
# escaped; only `footer` lines are Rich markup.
def print_error(headline: str, *details: str, title: str) -> None:
    body = f"[bold red]{escape(headline)}[/bold red]"
    if details:
        body += "\n\n" + "\n".join(f"[dim]{escape(line)}[/dim]" for line in details)
    err_console.print(Panel(body, title=title, border_style="red"))


def print_success(
    headline: str,
    *details: str,
    title: str,
    headline_style: str = "bold green",
    border_style: str = "green",
    footer: Iterable[str] = (),
) -> None:
    body = f"[{headline_style}]{escape(headline)}[/{headline_style}]"
    if details:
        body += "\n\n" + "\n".join(f"[dim]{escape(line)}[/dim]" for line in details)
    if footer:
        body += "\n\n" + "\n".join(footer)
    console.print(Panel(body, title=title, border_style=border_style))
