import hmac
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from jwt_toolkit.core.encoding import base64_decode_padded

ENCODINGS = ("utf-8", "hex", "base64", "all")

# Rough number of candidates each line expands to, for progress estimates.
ENCODING_MULTIPLIER = {"utf-8": 1, "hex": 1, "base64": 1, "all": 3}

_LABEL_SUFFIX = {"utf-8": "", "hex": " [hex]", "base64": " [b64]"}


@dataclass(frozen=True)
class Candidate:
    # The line exactly as the wordlist holds it, minus its line ending.
    source: bytes
    # The bytes used as the HMAC key once `source` is read with `encoding`.
    key: bytes
    # "utf-8", "hex", or "base64".
    encoding: str

    @property
    def label(self) -> str:
        return self.source.decode("utf-8", errors="replace") + _LABEL_SUFFIX[self.encoding]


def iter_lines(path: Path) -> Iterator[bytes]:
    # Streamed so multi-gigabyte lists stay flat in memory. Only the line ending
    # and a leading BOM are removed: spaces, tabs, and a leading "#" can all be
    # part of a real secret, and lines stay bytes so non-UTF-8 secrets are tried.
    with path.open("rb") as f:
        for index, line in enumerate(f):
            word = line.rstrip(b"\r\n")
            if index == 0:
                word = word.removeprefix(b"\xef\xbb\xbf")
            if word:
                yield word


def count_lines(path: Path) -> int:
    return sum(1 for _ in iter_lines(path))


def iter_candidates(path: Path, encoding: str) -> Iterator[Candidate]:
    # Dedup is per line only (across the "all" expansions), so memory stays flat.
    for raw in iter_lines(path):
        seen: set[bytes] = set()
        for name, key in _interpretations(raw, encoding):
            if key not in seen:
                seen.add(key)
                yield Candidate(source=raw, key=key, encoding=name)


def contains_secret(path: Path, secret: bytes) -> bool:
    # Reads every line, matched or not, so the time taken does not depend on
    # where (or whether) the secret appears.
    found = False
    for line in iter_lines(path):
        found |= hmac.compare_digest(line, secret)
    return found


def _interpretations(raw: bytes, encoding: str) -> Iterator[tuple[str, bytes]]:
    if encoding in ("utf-8", "all"):
        yield "utf-8", raw
    text = raw.decode("utf-8", errors="replace")
    decoders: tuple[tuple[str, Callable[[str], bytes]], ...] = (
        ("hex", bytes.fromhex),
        ("base64", base64_decode_padded),
    )
    for name, decode in decoders:
        if encoding not in (name, "all"):
            continue
        try:
            key = decode(text)
        except ValueError:
            continue
        yield name, key
