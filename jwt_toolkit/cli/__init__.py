import os

import click

from jwt_toolkit import __version__
from jwt_toolkit.cli.banner import COMMANDS, EXAMPLES, render_banner, render_help
from jwt_toolkit.commands.audit import audit
from jwt_toolkit.commands.crack import crack
from jwt_toolkit.commands.decode import decode
from jwt_toolkit.commands.diff import diff
from jwt_toolkit.commands.download_wordlists import download_wordlists
from jwt_toolkit.commands.forge import forge
from jwt_toolkit.commands.generate_secret import generate_secret
from jwt_toolkit.commands.sign import sign
from jwt_toolkit.commands.verify import verify

CLI_HELP = (
    "JWT Toolkit: a command-line toolkit for inspecting, verifying, cracking, "
    "and securing JSON Web Tokens.\n\n"
    "Built to expose how JWT signing works and where it breaks. Use it to audit tokens "
    "for misconfigurations, verify signatures and standard claims, brute-force weak HMAC "
    "secrets against a wordlist, and generate cryptographically strong secrets.\n\n"
    "\b\nCommands:\n"
    + "\n".join(f"  {name:<20}{summary}" for name, summary in COMMANDS)
    + "\n\n\b\nExamples:\n"
    + "\n".join(f"  {command}" for _, command in EXAMPLES)
    + "\n\nRun `jwt-toolkit COMMAND --help` for command-specific options.\n"
)


class _ToolkitGroup(click.Group):
    # CLI_HELP already lists every command with its full summary; Click's own
    # list would repeat it with truncated text.
    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        pass


@click.group(
    cls=_ToolkitGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help=CLI_HELP,
)
@click.version_option(
    version=__version__,
    prog_name="jwt-toolkit",
    message="%(prog)s %(version)s",
)
@click.option(
    "--no-banner",
    is_flag=True,
    envvar="JWT_TOOLKIT_NO_BANNER",
    help="Suppress the startup banner (also: JWT_TOOLKIT_NO_BANNER=1).",
)
@click.option(
    "--quiet",
    is_flag=True,
    envvar="JWT_TOOLKIT_QUIET",
    help="Keep results and errors, drop the banner, progress, and hints (also: JWT_TOOLKIT_QUIET=1).",
)
@click.option(
    "--no-color",
    is_flag=True,
    envvar="NO_COLOR",
    help="Disable color output (also: NO_COLOR=1).",
)
@click.pass_context
def cli(ctx: click.Context, no_banner: bool, quiet: bool, no_color: bool) -> None:
    # The lazy consoles read these at print time. They are removed again when the
    # command finishes so in-process callers do not inherit them.
    for name, enabled in (("NO_COLOR", no_color), ("JWT_TOOLKIT_QUIET", quiet)):
        if enabled and name not in os.environ:
            os.environ[name] = "1"
            ctx.call_on_close(lambda name=name: os.environ.pop(name, None))

    # The banner is only rendered for the bare `jwt-toolkit` invocation.
    # Printing it for every subcommand would corrupt --json output and noisily
    # prefix Click's usage errors, so it stays out of the subcommand path.
    if ctx.invoked_subcommand is None:
        if not (no_banner or quiet):
            render_banner()
        render_help()


cli.add_command(decode)
cli.add_command(sign)
cli.add_command(audit)
cli.add_command(generate_secret)
cli.add_command(verify)
cli.add_command(diff)
cli.add_command(forge)
cli.add_command(crack)
cli.add_command(download_wordlists)
