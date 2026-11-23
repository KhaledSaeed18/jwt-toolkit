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


def strict_json_loads(raw: str | bytes) -> object:
    # RFC 8259 has no NaN/Infinity; Python accepts them by default, and an
    # exponent like 1e400 silently overflows to inf. Both defeat exp/nbf checks.
    return json.loads(raw, parse_constant=_reject_constant, parse_float=_finite_float)
