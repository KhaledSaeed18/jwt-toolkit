import base64
import binascii
import json
import math
import re
from typing import Any

# JWT strips '=' padding by spec, so every encode trims it and every decode restores it.

# A decoded JSON object, such as a JWT header or claims set.
type JsonObject = dict[str, Any]


def _pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


_BASE64URL = re.compile(r"[A-Za-z0-9_-]*=*")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*=*")


def _strict_decode(value: str, alphabet: re.Pattern[str], altchars: bytes | None) -> bytes:
    # Python 3.15 stopped rejecting characters outside the alphabet in non-validating
    # mode, so the alphabet is checked here and the stdlib decode always validates.
    if not alphabet.fullmatch(value):
        raise binascii.Error("input contains characters outside the base64 alphabet")
    return base64.b64decode(_pad(value.rstrip("=")), altchars=altchars, validate=True)


def base64url_decode(value: str) -> bytes:
    return _strict_decode(value, _BASE64URL, b"-_")


def base64_decode_padded(value: str) -> bytes:
    # Standard base64 (not url-safe) with the same padding restoration —
    # used by `crack` when interpreting a wordlist entry as a base64 secret.
    return _strict_decode(value, _BASE64, None)


class NonFiniteNumberError(ValueError):
    pass


def _reject_constant(name: str) -> float:
    raise NonFiniteNumberError(name)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise NonFiniteNumberError(text)
    return value


# Real JWT headers and claims nest a few levels; anything deeper is hostile or broken.
MAX_JSON_DEPTH = 32


class DuplicateMemberError(ValueError):
    # RFC 7515 4 and RFC 7519 4 let a parser reject duplicate member names. Parsers
    # that keep the first or the last one disagree about what the token says.
    pass


class JsonTooDeepError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateMemberError(name)
        result[name] = value
    return result


def _check_depth(text: str) -> None:
    # Measured on the text before parsing, because how deep the parser recurses, and
    # whether it raises RecursionError, differs between Python versions. One pass with
    # no backtracking, so hostile input cannot make it slow.
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise JsonTooDeepError(depth)
        elif char in "]}":
            depth -= 1


def strict_json_loads(raw: str | bytes) -> object:
    # RFC 8259 has no NaN/Infinity; Python accepts them by default, and an
    # exponent like 1e400 silently overflows to inf. Both defeat exp/nbf checks.
    # Bytes must be UTF-8 (RFC 7519 7.2); json.loads would also detect UTF-16 and UTF-32.
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    _check_depth(text)
    return json.loads(
        text,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
        object_pairs_hook=_reject_duplicates,
    )
