import click

from jwt_toolkit.commands.audit import audit
from jwt_toolkit.commands.crack import crack
from jwt_toolkit.commands.download_wordlists import download_wordlists
from jwt_toolkit.commands.generate_secret import generate_secret
from jwt_toolkit.commands.verify import verify


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context):
    # Print the banner only when the user ran `jwt-toolkit` with no subcommand.
    # Printing it for every invocation corrupts --json output and noisily prefixes
    # Click's usage errors, so it stays out of the subcommand path.
    if ctx.invoked_subcommand is None:
        click.echo("Welcome to JWT Toolkit!")
        click.echo(ctx.get_help())


cli.add_command(audit)
cli.add_command(generate_secret)
cli.add_command(verify)
cli.add_command(crack)
cli.add_command(download_wordlists)
