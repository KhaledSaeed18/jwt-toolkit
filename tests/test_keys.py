import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa

from jwt_toolkit.core.algorithms import ALGORITHMS, Family
from jwt_toolkit.core.crypto import sign_with_key, verify_with_key
from jwt_toolkit.core.encoding import base64url_encode
from jwt_toolkit.core.errors import (
    KeyAlgorithmMismatchError,
    KeyParseError,
    KeyPassphraseRequiredError,
    UnsupportedAlgorithmError,
)
from jwt_toolkit.core.jwks import jwk_to_public_key
from jwt_toolkit.core.keys import (
    HmacKey,
    PrivateKey,
    PublicKey,
    load_private_key,
    load_public_key,
)
from tests.helpers import self_signed_cert_pem
from tests.test_jwks import _rsa_jwk

MESSAGE = b"eyJhbGciOiJ0ZXN0In0.eyJzdWIiOiIxIn0"


_FIXTURES = {
    "RSA": "rsa_keypair",
    "P-256": "ec_p256_keypair",
    "P-384": "ec_p384_keypair",
    "P-521": "ec_p521_keypair",
    "Ed25519": "ed25519_keypair",
    "Ed448": "ed448_keypair",
}


@pytest.fixture
def keypairs(request):
    return {kind: request.getfixturevalue(name) for kind, name in _FIXTURES.items()}


# Which algorithms each key may use. Everything else must be refused.
ALLOWED = {
    "RSA": {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"},
    "P-256": {"ES256"},
    "P-384": {"ES384"},
    "P-521": {"ES512"},
    "Ed25519": {"EdDSA", "Ed25519"},
    "Ed448": {"EdDSA", "Ed448"},
}


@pytest.mark.parametrize("kind", list(ALLOWED))
@pytest.mark.parametrize("alg", list(ALGORITHMS))
def test_key_family_matrix(keypairs, kind, alg):
    private = load_private_key(keypairs[kind].private_pem)
    public = load_public_key(keypairs[kind].public_pem)
    spec = ALGORITHMS[alg]
    if alg in ALLOWED[kind]:
        signature = sign_with_key(MESSAGE, private, spec)

        assert verify_with_key(MESSAGE, base64url_encode(signature), public, spec)
        return
    with pytest.raises(UnsupportedAlgorithmError if spec.is_hmac else KeyAlgorithmMismatchError):
        private.check_algorithm(spec)
    with pytest.raises(UnsupportedAlgorithmError if spec.is_hmac else KeyAlgorithmMismatchError):
        public.check_algorithm(spec)


@pytest.mark.parametrize("alg", [a for a, s in ALGORITHMS.items() if s.family is not Family.HMAC])
def test_hmac_key_never_verifies_an_asymmetric_algorithm(alg):
    with pytest.raises(KeyAlgorithmMismatchError):
        verify_with_key(MESSAGE, "c2ln", HmacKey(b"secret"), ALGORITHMS[alg])


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_public_key_never_verifies_hmac(rsa_keypair, alg):
    # Algorithm confusion (CVE-2016-10555) is refused by the key itself.
    public = load_public_key(rsa_keypair.public_pem)
    with pytest.raises(UnsupportedAlgorithmError, match="Unsupported asymmetric algorithm"):
        verify_with_key(MESSAGE, "c2ln", public, ALGORITHMS[alg])


def test_hmac_round_trip_and_tamper():
    key = HmacKey.from_text("synthetic-secret")

    signature = base64url_encode(sign_with_key(MESSAGE, key, ALGORITHMS["HS256"]))
    assert verify_with_key(MESSAGE, signature, key, ALGORITHMS["HS256"])
    assert not verify_with_key(MESSAGE + b"x", signature, key, ALGORITHMS["HS256"])
    assert not verify_with_key(MESSAGE, signature, HmacKey(b"other"), ALGORITHMS["HS256"])


def test_keys_never_show_secret_material(rsa_keypair):
    assert "synthetic" not in repr(HmacKey.from_text("synthetic-secret"))
    assert "BEGIN" not in repr(load_private_key(rsa_keypair.private_pem))


def test_certificate_loads_as_public_key(rsa_keypair):
    cert = self_signed_cert_pem(rsa_keypair.private_pem)
    assert isinstance(load_public_key(cert), PublicKey)


@pytest.mark.parametrize(
    "data",
    [b"", b"not a key", b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n"],
)
def test_malformed_public_key(data):
    with pytest.raises(KeyParseError, match="Could not parse PEM public key"):
        load_public_key(data)


def test_malformed_private_key():
    with pytest.raises(KeyParseError, match="Could not parse PEM private key"):
        load_private_key(b"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")


def test_encrypted_private_key_needs_the_right_passphrase(rsa_keypair):
    key = serialization.load_pem_private_key(rsa_keypair.private_pem, password=None)
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"synthetic-passphrase"),
    )
    with pytest.raises(KeyPassphraseRequiredError):
        load_private_key(encrypted)
    with pytest.raises(KeyParseError, match="wrong passphrase"):
        load_private_key(encrypted, passphrase=b"wrong")
    assert isinstance(load_private_key(encrypted, passphrase=b"synthetic-passphrase"), PrivateKey)
    with pytest.raises(KeyParseError, match="not encrypted"):
        load_private_key(rsa_keypair.private_pem, passphrase=b"unneeded")


def test_unusable_key_types_are_refused():
    dsa_key = dsa.generate_private_key(key_size=2048)
    private_pem = dsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = dsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(KeyParseError, match="cannot sign a JWS"):
        load_private_key(private_pem)
    with pytest.raises(KeyParseError, match="cannot verify a JWS"):
        load_public_key(public_pem)


def test_default_algorithm_follows_the_key(keypairs):
    expected = {
        "RSA": "RS256",
        "P-256": "ES256",
        "P-384": "ES384",
        "P-521": "ES512",
        "Ed25519": "Ed25519",
        "Ed448": "Ed448",
    }
    for kind, alg in expected.items():
        assert load_private_key(keypairs[kind].private_pem).default_algorithm() == alg


def test_jwk_becomes_a_public_key(rsa_keypair):
    public = serialization.load_pem_public_key(rsa_keypair.public_pem)
    key = jwk_to_public_key(_rsa_jwk(public), "RS256")
    assert isinstance(key, PublicKey)
    key.check_algorithm(ALGORITHMS["PS256"])
