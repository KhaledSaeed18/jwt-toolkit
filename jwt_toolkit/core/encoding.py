import base64
import binascii
import json
import math
from typing import Any

# JWT strips '=' padding by spec, so every encode trims it and every decode restores it.

# A decoded JSON object, such as a JWT header or claims set.
type JsonObject = dict[str, Any]


def _pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def base64url_decode(value: str) -> bytes:
    # The stdlib raises a bare ValueError for non-ASCII input; callers expect binascii.Error.
    if not value.isascii():
        raise binascii.Error("base64url input must be ASCII")
    return base64.urlsafe_b64decode(_pad(value))


def base64_decode_padded(value: str) -> bytes:
    # Standard base64 (not url-safe) with the same padding restoration —
    # used by `crack` when interpreting a wordlist entry as a base64 secret.
    return base64.b64decode(_pad(value))


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
