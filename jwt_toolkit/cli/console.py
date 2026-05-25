from rich.console import Console

# One shared Console for the whole CLI — Rich expects a singleton for consistent
# styling and width detection.
console = Console()
