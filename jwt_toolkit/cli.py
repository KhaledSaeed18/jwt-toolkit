import click
from jwt_toolkit.commands.inspect import inspect
from jwt_toolkit.commands.generate_secret import generate_secret
from jwt_toolkit.commands.verify import verify
from jwt_toolkit.commands.crack import crack
from jwt_toolkit.commands.download_wordlists import download_wordlists

@click.group()
def cli():
    print("Welcome to JWT Toolkit!")

cli.add_command(inspect)
cli.add_command(generate_secret)
cli.add_command(verify)
cli.add_command(crack)
cli.add_command(download_wordlists)