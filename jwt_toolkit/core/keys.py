"""Key objects for signing and verification.

The supplied key decides which algorithms may be used: an HMAC secret only
verifies HS*, an RSA key only RS*/PS*, an EC key only the ES* for its curve, an
OKP key only EdDSA for its curve. Nothing here trusts a token's `alg` header to
pick the algorithm family (algorithm confusion, CVE-2016-10555).
"""

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from jwt_toolkit.core.algorithms import ALGORITHMS, AlgorithmSpec, Family
from jwt_toolkit.core.errors import (
    KeyAlgorithmMismatchError,
    KeyParseError,
    KeyPassphraseRequiredError,
    UnsupportedAlgorithmError,
)

type SigningPrivateKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)
type VerifyingPublicKey = (
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey
)
_SIGNING_PRIVATE_KEY_TYPES = (
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)
_VERIFYING_PUBLIC_KEY_TYPES = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
)


@dataclass(frozen=True)
class HmacKey:
    # The shared secret as bytes. `--secret` text is UTF-8 encoded by the caller.
    secret: bytes

    @classmethod
    def from_text(cls, secret: str) -> "HmacKey":
        return cls(secret.encode())

    def check_algorithm(self, spec: AlgorithmSpec) -> None:
        if not spec.is_hmac:
            raise KeyAlgorithmMismatchError(
                f"{spec.name} cannot be used with an HMAC secret; it needs a public or private key"
            )

    def __repr__(self) -> str:
        # Never show the secret, not even in a traceback or a debugger.
        return "HmacKey(<redacted>)"


@dataclass(frozen=True)
class PublicKey:
    key: VerifyingPublicKey

    def check_algorithm(self, spec: AlgorithmSpec) -> None:
        ensure_key_matches_algorithm(self.key, spec.name, is_private=False)


@dataclass(frozen=True)
class PrivateKey:
    key: SigningPrivateKey

    def check_algorithm(self, spec: AlgorithmSpec) -> None:
        ensure_key_matches_algorithm(self.key, spec.name, is_private=True)

    def default_algorithm(self) -> str:
        # RS256 for RSA, the ES* that RFC 7518 3.4 pairs with the curve, and the
        # fully-specified EdDSA name (RFC 9864).
        return default_algorithm_for(self.key)

    def __repr__(self) -> str:
        return f"PrivateKey(<{type(self.key).__name__}>)"


type VerificationKey = HmacKey | PublicKey
type SigningKey = HmacKey | PrivateKey


def parse_private_key(pem: bytes, passphrase: bytes | None = None) -> PrivateKeyTypes:
    try:
        return serialization.load_pem_private_key(pem, password=passphrase)
    except TypeError as exc:
        # cryptography signals passphrase/encryption mismatches with TypeError.
        if passphrase is None:
            raise KeyPassphraseRequiredError() from exc
        raise KeyParseError("A passphrase was given but the private key is not encrypted") from exc
    except ValueError as exc:
        if passphrase is not None and b"ENCRYPTED" in pem:
            raise KeyParseError("Could not decrypt the private key: wrong passphrase") from exc
        raise KeyParseError(f"Could not parse PEM private key: {exc}") from exc


def parse_public_key(pem: bytes) -> PublicKeyTypes:
    try:
        if b"-----BEGIN CERTIFICATE-----" in pem:
            # Identity providers often publish signing keys as certificates. The
            # certificate is only a key container here: no chain or validity check.
            return x509.load_pem_x509_certificate(pem).public_key()
        return serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise KeyParseError(f"Could not parse PEM public key or certificate: {exc}") from exc


def load_private_key(pem: bytes, *, passphrase: bytes | None = None) -> PrivateKey:
    return as_private_key(parse_private_key(pem, passphrase))


def as_private_key(key: PrivateKeyTypes) -> PrivateKey:
    if not isinstance(key, _SIGNING_PRIVATE_KEY_TYPES):
        raise KeyParseError(f"A {type(key).__name__} cannot sign a JWS")
    return PrivateKey(key)


def load_public_key(pem: bytes) -> PublicKey:
    # A PEM public key or an X.509 certificate in PEM.
    return as_public_key(parse_public_key(pem))


def load_public_key_for(pem: bytes, spec: AlgorithmSpec) -> PublicKey:
    # Parse, then check the family before the key type, so a key for another
    # algorithm is reported as a mismatch rather than as an unusable key.
    raw = parse_public_key(pem)
    ensure_key_matches_algorithm(raw, spec.name, is_private=False)
    return as_public_key(raw)


def as_public_key(key: PublicKeyTypes) -> PublicKey:
    if not isinstance(key, _VERIFYING_PUBLIC_KEY_TYPES):
        raise KeyParseError(f"A {type(key).__name__} cannot verify a JWS")
    return PublicKey(key)


def default_algorithm_for(key: PrivateKeyTypes) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        for spec in ALGORITHMS.values():
            if spec.curve is not None and isinstance(key.curve, spec.curve):
                return spec.name
        raise KeyAlgorithmMismatchError(f"EC curve {key.curve.name} has no JWS algorithm")
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    raise KeyParseError(f"A {type(key).__name__} cannot sign a JWS")


def ensure_key_matches_algorithm(
    key: PrivateKeyTypes | PublicKeyTypes, alg: str, *, is_private: bool
) -> None:
    spec = ALGORITHMS.get(alg)
    role = "private" if is_private else "public"
    if spec is None or spec.is_hmac:
        raise UnsupportedAlgorithmError(f"Unsupported asymmetric algorithm: {alg}")
    if spec.family in (Family.RSA, Family.PSS):
        expected = rsa.RSAPrivateKey if is_private else rsa.RSAPublicKey
        if not isinstance(key, expected):
            raise KeyAlgorithmMismatchError(
                f"{alg} requires an RSA {role} key, got {type(key).__name__}"
            )
        return
    if spec.family is Family.EC:
        if not isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) or (
            isinstance(key, ec.EllipticCurvePrivateKey) is not is_private
        ):
            raise KeyAlgorithmMismatchError(
                f"{alg} requires an EC {role} key, got {type(key).__name__}"
            )
        expected_curve = spec.curve
        if expected_curve is None or not isinstance(key.curve, expected_curve):
            raise KeyAlgorithmMismatchError(
                f"{alg} requires curve {expected_curve.name if expected_curve else '?'}, "
                f"got {key.curve.name}"
            )
        return
    expected_okp = spec.okp_private_types if is_private else spec.okp_public_types
    if not isinstance(key, expected_okp):
        curve = "an Ed25519 or Ed448" if alg == "EdDSA" else f"an {alg}"
        raise KeyAlgorithmMismatchError(
            f"{alg} requires {curve} {role} key, got {type(key).__name__}"
        )
