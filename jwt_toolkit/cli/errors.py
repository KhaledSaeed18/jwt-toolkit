import json
from typing import Any

import click

from jwt_toolkit.cli.panels import print_error
from jwt_toolkit.core.errors import JwtToolkitError

# Stable schema version shared by every command that emits --json.
JSON_SCHEMA_VERSION = "0.1"


def error_document(exc: JwtToolkitError) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "error": exc.code,
        "message": exc.headline,
        "detail": list(exc.details),
    }
    if exc.cause is not None:
        document["cause"] = exc.cause
    document.update(exc.extra)
    return document


def render_error(exc: JwtToolkitError, *, as_json: bool) -> None:
    # A JSON error document on stdout under --json, a panel on stderr otherwise.
    if as_json:
        click.echo(json.dumps(error_document(exc), indent=2))
    else:
        print_error(exc.headline, *exc.details, title=exc.title)


def reported_as(
    exc: JwtToolkitError,
    *,
    code: str,
    title: str,
    headline: str | None = None,
) -> JwtToolkitError:
    # Reports a core error under the broad code a command has always used, keeping
    # the specific code as `cause`. With a headline, the core message becomes the
    # detail line; without one, it is the headline.
    return JwtToolkitError(
        headline=headline or str(exc),
        details=(str(exc),) if headline else (),
        code=code,
        title=title,
        cause=exc.code,
        extra=exc.extra,
    )


class ToolkitCommand(click.Command):
    # The single error boundary: any JwtToolkitError a command raises is rendered
    # once, as a panel or as the --json error document, and exits with its code.
    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except JwtToolkitError as exc:
            render_error(exc, as_json=bool(ctx.params.get("as_json")))
            ctx.exit(exc.exit_code)
