import click

@click.command()
def generate_secret():
    click.echo("Generating a random secret key for JWT signing")