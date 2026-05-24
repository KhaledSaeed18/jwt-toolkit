import click

@click.command()
@click.argument("token")
def inspect(token):
    click.echo(f"Inspecting JWT token: {token}")