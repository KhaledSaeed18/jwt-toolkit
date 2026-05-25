from importlib.metadata import PackageNotFoundError, version
import click
from jwt_toolkit.cli.banner import render_banner, render_help
from jwt_toolkit.commands.audit import audit
from jwt_toolkit.commands.crack import crack
from jwt_toolkit.commands.download_wordlists import download_wordlists
from jwt_toolkit.commands.generate_secret import generate_secret
from jwt_toolkit.commands.verify import verify

try:
    __version__ = version("jwt-toolkit")
except PackageNotFoundError:
    __version__ = "0.0.0"

CLI_HELP = """\
JWT Toolkit — a command-line toolkit for inspecting, verifying, cracking,
and securing JSON Web Tokens.

Built to expose how JWT signing works and where it breaks. Use it to audit
tokens for misconfigurations, verify signatures and standard claims,
brute-force weak HMAC secrets against a wordlist, and generate
cryptographically strong secrets.

\b
Commands:
  audit               Static security analysis of a JWT (no key required).
  verify              Verify the signature and standard claims of a JWT.
  crack               Brute-force a weak HMAC secret using a wordlist.
  generate-secret     Emit a cryptographically strong random secret.
  download-wordlists  Fetch the latest common-secrets wordlist.

\b
Examples:
  jwt-toolkit audit <token>
  jwt-toolkit audit <token> --strict --json
  jwt-toolkit verify <token> --secret <secret> --issuer auth.example.com
  jwt-toolkit crack <token> wordlists/common-secrets.txt --threads 8
  jwt-toolkit generate-secret --bits 256 --encoding base64
  jwt-toolkit download-wordlists --output-dir wordlists

Run `jwt-toolkit COMMAND --help` for command-specific options.
"""

@click.group(
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
@click.pass_context
def cli(ctx: click.Context, no_banner: bool):
    # The banner is only rendered for the bare `jwt-toolkit` invocation.
    # Printing it for every subcommand would corrupt --json output and noisily
    # prefix Click's usage errors, so it stays out of the subcommand path.
    if ctx.invoked_subcommand is None:
        if not no_banner:
            render_banner()
        render_help()

cli.add_command(audit)
cli.add_command(generate_secret)
cli.add_command(verify)
cli.add_command(crack)
cli.add_command(download_wordlists)
