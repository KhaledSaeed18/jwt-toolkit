from collections.abc import Iterable

from rich.panel import Panel

from jwt_toolkit.cli.console import console


def print_error(headline: str, *details: str, title: str) -> None:
    body = f"[bold red]{headline}[/bold red]"
    if details:
        body += "\n\n" + "\n".join(f"[dim]{line}[/dim]" for line in details)
    console.print(Panel(body, title=title, border_style="red"))


def print_success(
    headline: str,
    *details: str,
    title: str,
    headline_style: str = "bold green",
    border_style: str = "green",
    footer: Iterable[str] = (),
) -> None:
    body = f"[{headline_style}]{headline}[/{headline_style}]"
    if details:
        body += "\n\n" + "\n".join(f"[dim]{line}[/dim]" for line in details)
    if footer:
        body += "\n\n" + "\n".join(footer)
    console.print(Panel(body, title=title, border_style=border_style))
