"""Shared test utilities — plain functions, no pytest fixtures.

Fixtures in conftest.py wrap these factories. Tests can call either,
but prefer fixtures for the common case (less boilerplate, no import).
"""

import datetime
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

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


def self_signed_cert_pem(private_pem: bytes) -> bytes:
    """Wrap a test key's public half in a one-day self-signed certificate."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jwt-toolkit test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)
