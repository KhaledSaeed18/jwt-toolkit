"""Shared test utilities — plain functions, no pytest fixtures.

Fixtures in conftest.py wrap these factories. Tests can call either,
but prefer fixtures for the common case (less boilerplate, no import).
"""

import json

from jwt_toolkit.core.crypto import sign as _sign
from jwt_toolkit.core.encoding import base64url_encode

# Single source of truth for the test HMAC secret. Imported by both
# helpers and conftest fixtures so the value never drifts.
TEST_SECRET = "testsecret"


def _encode_part(obj: dict) -> str:
    return base64url_encode(json.dumps(obj, separators=(",", ":")).encode())


def make_token(
    payload: dict,
    secret: str = TEST_SECRET,
    alg: str = "HS256",
    header_override: dict | None = None,
) -> str:
    """Build a real signed JWT for use in tests."""
    header = header_override if header_override is not None else {"alg": alg, "typ": "JWT"}
    h = _encode_part(header)
    p = _encode_part(payload)
    sig = _sign(h, p, secret, alg)
    return f"{h}.{p}.{sig}"


def make_unsigned_token(payload: dict) -> str:
    """Build an alg:none token (empty signature)."""
    h = _encode_part({"alg": "none", "typ": "JWT"})
    p = _encode_part(payload)
    return f"{h}.{p}."


def make_rs256_token(payload: dict) -> str:
    """Build a plausible-looking RS256 token (unsigned, for rejection tests)."""
    h = _encode_part({"alg": "RS256", "typ": "JWT"})
    p = _encode_part(payload)
    return f"{h}.{p}.fakesig"
