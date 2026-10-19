from importlib.resources import files
from pathlib import Path

BUNDLED_WORDLIST_NAME = "common-secrets.txt"


def bundled_wordlist() -> Path | None:
    # Wheels ship the list as package data; a source checkout keeps it at the
    # repository root, which is where editable installs find it.
    packaged = files("jwt_toolkit") / "wordlists" / BUNDLED_WORDLIST_NAME
    if packaged.is_file():
        return Path(str(packaged))
    checkout = Path(__file__).resolve().parents[2] / "wordlists" / BUNDLED_WORDLIST_NAME
    return checkout if checkout.is_file() else None
