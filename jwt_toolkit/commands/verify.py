import click

@click.command()
@click.argument("token")
def verify(token):
    click.echo(f"Verifying JWT token: {token}")