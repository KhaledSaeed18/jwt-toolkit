"""Project-wide pytest fixtures.

Anything defined here is auto-injected into any test in `tests/` that
declares a matching argument — no imports required.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tests.helpers import TEST_SECRET, make_token, make_unsigned_token


@dataclass(frozen=True)
class KeyPair:
    """Holds PEM-encoded key material for an asymmetric algorithm family."""

    private_pem: bytes
    public_pem: bytes


def _to_pem(key) -> KeyPair:
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(private_pem=private_pem, public_pem=public_pem)


# Far-future expiry used by valid_token. A literal constant keeps tests
# readable without sprinkling magic numbers around.
_FAR_FUTURE = 9_999_999_999


@pytest.fixture
def runner() -> CliRunner:
    """Click test runner — one per test, isolated stdout/stderr."""
    return CliRunner()


@pytest.fixture
def test_secret() -> str:
    """The shared HS256 secret used by token factories."""
    return TEST_SECRET


@pytest.fixture
def now() -> int:
    """Frozen `int(time.time())` snapshot for the duration of the test.

    Captured once so multiple `now + delta` calls in the same test stay
    consistent — repeated inline `int(time.time())` does not guarantee that.
    """
    return int(time.time())


@pytest.fixture
def token_factory() -> Callable[..., str]:
    """Factory fixture returning `make_token` — preferred entry point for tests.

    Usage:
        def test_x(token_factory):
            t = token_factory({"sub": "1"}, alg="HS384")
    """
    return make_token


@pytest.fixture
def unsigned_token_factory() -> Callable[..., str]:
    """Factory for alg:none tokens."""
    return make_unsigned_token


@pytest.fixture
def valid_token() -> str:
    """HS256 JWT with a far-future exp and the shared test secret."""
    return make_token({"sub": "1", "exp": _FAR_FUTURE})


# Asymmetric key fixtures — session-scoped because RSA keygen is expensive.
# A single 2048-bit RSA key covers both RS* and PS* algorithms.


@pytest.fixture(scope="session")
def rsa_keypair() -> KeyPair:
    return _to_pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def ec_p256_keypair() -> KeyPair:
    return _to_pem(ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture(scope="session")
def ec_p384_keypair() -> KeyPair:
    return _to_pem(ec.generate_private_key(ec.SECP384R1()))


@pytest.fixture(scope="session")
def ec_p521_keypair() -> KeyPair:
    return _to_pem(ec.generate_private_key(ec.SECP521R1()))


@pytest.fixture
def keypair_for(
    rsa_keypair: KeyPair,
    ec_p256_keypair: KeyPair,
    ec_p384_keypair: KeyPair,
    ec_p521_keypair: KeyPair,
) -> Callable[[str], KeyPair]:
    """Return the keypair appropriate for a given JWS alg."""
    by_alg: dict[str, KeyPair] = {
        "RS256": rsa_keypair,
        "RS384": rsa_keypair,
        "RS512": rsa_keypair,
        "PS256": rsa_keypair,
        "PS384": rsa_keypair,
        "PS512": rsa_keypair,
        "ES256": ec_p256_keypair,
        "ES384": ec_p384_keypair,
        "ES512": ec_p521_keypair,
    }

    def _lookup(alg: str) -> KeyPair:
        return by_alg[alg.upper()]

    return _lookup
