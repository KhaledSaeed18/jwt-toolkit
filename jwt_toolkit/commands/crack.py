import click

@click.command()
@click.argument("token")
@click.argument("wordlist")
def crack(token, wordlist):
    click.echo("Cracking JWT token with wordlist")
    click.echo(f"Token: {token}")
    click.echo(f"Wordlist: {wordlist}")