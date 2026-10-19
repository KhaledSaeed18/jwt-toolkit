import hashlib
import hmac
from collections.abc import Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from jwt_toolkit.core.encoding import base64url_decode, base64url_encode
from jwt_toolkit.core.errors import KeyPassphraseRequiredError

# Crypto module — signing and verification for the JWS algorithms we support.
# HMAC lives at the top of the module; asymmetric primitives follow.

# HMAC algorithms — symmetric, shared-secret. Kept as a dict so `crack` can iterate
# `(alg, digestmod)` directly. Public API: do not rename.
SUPPORTED_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# Asymmetric algorithm families — split by primitive so dispatchers can branch
# without re-deriving the family from the alg string.
RSA_ALGORITHMS = frozenset({"RS256", "RS384", "RS512"})
EC_ALGORITHMS = frozenset({"ES256", "ES384", "ES512"})
PSS_ALGORITHMS = frozenset({"PS256", "PS384", "PS512"})
# RFC 8037 EdDSA. RFC 9864 deprecates the polymorphic "EdDSA" in favour of the
# fully-specified Ed25519/Ed448, but existing deployments still emit it.
OKP_ALGORITHMS = frozenset({"EdDSA", "Ed25519", "Ed448"})
ASYMMETRIC_ALGORITHMS = RSA_ALGORITHMS | EC_ALGORITHMS | PSS_ALGORITHMS | OKP_ALGORITHMS

# Union of every algorithm the toolkit can produce or verify a signature for.
ALL_SIGNING_ALGORITHMS = frozenset(SUPPORTED_ALGORITHMS) | ASYMMETRIC_ALGORITHMS

_CANONICAL_BY_UPPER = {name.upper(): name for name in ALL_SIGNING_ALGORITHMS}


def canonical_algorithm(name: str) -> str | None:
    # Case-insensitive lookup for callers passing a user-typed name. Token
    # headers must still match the registered spelling exactly (RFC 7515 4.1.1).
    return _CANONICAL_BY_UPPER.get(name.upper())


# Hash algorithm to use for each asymmetric alg. The trailing digits in the JWS
# alg name (e.g. "RS256" → SHA-256) determine the hash, regardless of family.
# Typed as a callable factory so mypy doesn't see the values as the abstract
# `type[HashAlgorithm]` base — the dict holds concrete constructors.
_HASH_BY_ALG: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
    "PS256": hashes.SHA256,
    "PS384": hashes.SHA384,
    "PS512": hashes.SHA512,
    "ES256": hashes.SHA256,
    "ES384": hashes.SHA384,
    "ES512": hashes.SHA512,
}

# Required curve for each ES* alg per RFC 7518 §3.4. Other curves must be rejected
# even if cryptography would otherwise accept them — using ES256 with SECP384R1
# is a JWS compliance bug and would not interoperate.
_EC_CURVE_BY_ALG: dict[str, type[ec.EllipticCurve]] = {
    "ES256": ec.SECP256R1,
    "ES384": ec.SECP384R1,
    "ES512": ec.SECP521R1,
}

# Key classes accepted for each EdDSA alg; plain "EdDSA" takes its curve from the key.
_OKP_PRIVATE_KEY_TYPES: dict[str, tuple[type, ...]] = {
    "EdDSA": (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
    "Ed25519": (ed25519.Ed25519PrivateKey,),
    "Ed448": (ed448.Ed448PrivateKey,),
}
_OKP_PUBLIC_KEY_TYPES: dict[str, tuple[type, ...]] = {
    "EdDSA": (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
    "Ed25519": (ed25519.Ed25519PublicKey,),
    "Ed448": (ed448.Ed448PublicKey,),
}

# Raw component size (in bytes) for each ES* signature. JWS ECDSA signatures are
# fixed-width r || s; cryptography emits DER, so we must convert in both directions.
_EC_RAW_SIG_HALF_BYTES = {
    "ES256": 32,
    "ES384": 48,
    "ES512": 66,
}


# HMAC sign and verify — public API unchanged.


def sign(header_b64: str, payload_b64: str, secret: str, alg: str = "HS256") -> str:
    digestmod = SUPPORTED_ALGORITHMS.get(alg.upper())
    if digestmod is None:
        raise ValueError(
            f"Unsupported algorithm: {alg}. Supported: {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    # Signing input is exactly header_b64 + "." + payload_b64 as defined by the JWT spec.
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), message, digestmod).digest()
    return base64url_encode(signature)


def verify_signature(
    header_b64: str, payload_b64: str, signature: str, secret: str, alg: str = "HS256"
) -> bool:
    expected = sign(header_b64, payload_b64, secret, alg)
    # compare_digest is timing-safe. It only accepts ASCII str, and the signature
    # segment comes from the token unvalidated, so both sides are compared as bytes.
    return hmac.compare_digest(expected.encode(), signature.encode("utf-8", "surrogatepass"))


# Asymmetric sign and verify.
#
# Keys are supplied as PEM bytes so callers don't need to import cryptography
# types. Errors are normalised to `ValueError` so the CLI layer can render them
# uniformly without catching library-specific exception classes.


def sign_asymmetric(
    header_b64: str,
    payload_b64: str,
    private_key_pem: bytes,
    alg: str,
    *,
    passphrase: bytes | None = None,
) -> str:
    alg = canonical_algorithm(alg) or alg
    if alg not in ASYMMETRIC_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {alg}. "
            f"Asymmetric algorithms: {', '.join(sorted(ASYMMETRIC_ALGORITHMS))}"
        )
    private_key = _load_private_key(private_key_pem, alg, passphrase=passphrase)
    message = f"{header_b64}.{payload_b64}".encode()
    raw_sig = _sign_with_private_key(private_key, message, alg)
    return base64url_encode(raw_sig)


def verify_asymmetric(
    header_b64: str,
    payload_b64: str,
    signature: str,
    public_key_pem: bytes,
    alg: str,
) -> bool:
    alg = canonical_algorithm(alg) or alg
    if alg not in ASYMMETRIC_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {alg}. "
            f"Asymmetric algorithms: {', '.join(sorted(ASYMMETRIC_ALGORITHMS))}"
        )
    public_key = _load_public_key(public_key_pem, alg)
    message = f"{header_b64}.{payload_b64}".encode()
    try:
        raw_sig = base64url_decode(signature)
    except (ValueError, TypeError):
        return False
    try:
        _verify_with_public_key(public_key, message, raw_sig, alg)
    except (InvalidSignature, ValueError):
        return False
    return True


# Internal helpers — kept private so the dispatch shape can change without
# breaking importers.


def algorithm_for_private_key(pem: bytes, *, passphrase: bytes | None = None) -> str:
    # The default algorithm for a key: RS256 for RSA, the ES* that RFC 7518 3.4
    # pairs with the curve, and the fully-specified EdDSA name (RFC 9864).
    key = _parse_private_key(pem, passphrase)
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        for alg, curve in _EC_CURVE_BY_ALG.items():
            if isinstance(key.curve, curve):
                return alg
        raise ValueError(f"EC curve {key.curve.name} has no JWS algorithm")
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    raise ValueError(f"A {type(key).__name__} cannot sign a JWS")


def _load_private_key(pem: bytes, alg: str, *, passphrase: bytes | None = None):
    key = _parse_private_key(pem, passphrase)
    _ensure_key_matches_alg(key, alg, is_private=True)
    return key


def _parse_private_key(pem: bytes, passphrase: bytes | None):
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase)
    except TypeError as exc:
        # cryptography signals passphrase/encryption mismatches with TypeError.
        if passphrase is None:
            raise KeyPassphraseRequiredError() from exc
        raise ValueError("A passphrase was given but the private key is not encrypted") from exc
    except ValueError as exc:
        if passphrase is not None and b"ENCRYPTED" in pem:
            raise ValueError("Could not decrypt the private key: wrong passphrase") from exc
        raise ValueError(f"Could not parse PEM private key: {exc}") from exc
    return key


def _load_public_key(pem: bytes, alg: str):
    key: PublicKeyTypes
    try:
        if b"-----BEGIN CERTIFICATE-----" in pem:
            # Identity providers often publish signing keys as certificates. The
            # certificate is only a key container here: no chain or validity check.
            key = x509.load_pem_x509_certificate(pem).public_key()
        else:
            key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Could not parse PEM public key or certificate: {exc}") from exc
    _ensure_key_matches_alg(key, alg, is_private=False)
    return key


def _ensure_key_matches_alg(key, alg: str, *, is_private: bool) -> None:
    role = "private" if is_private else "public"
    if alg in RSA_ALGORITHMS or alg in PSS_ALGORITHMS:
        expected = rsa.RSAPrivateKey if is_private else rsa.RSAPublicKey
        if not isinstance(key, expected):
            raise ValueError(f"{alg} requires an RSA {role} key, got {type(key).__name__}")
        return
    if alg in EC_ALGORITHMS:
        expected_ec = ec.EllipticCurvePrivateKey if is_private else ec.EllipticCurvePublicKey
        if not isinstance(key, expected_ec):
            raise ValueError(f"{alg} requires an EC {role} key, got {type(key).__name__}")
        expected_curve = _EC_CURVE_BY_ALG[alg]
        if not isinstance(key.curve, expected_curve):
            raise ValueError(f"{alg} requires curve {expected_curve.name}, got {key.curve.name}")
        return
    if alg in OKP_ALGORITHMS:
        expected_okp = (_OKP_PRIVATE_KEY_TYPES if is_private else _OKP_PUBLIC_KEY_TYPES)[alg]
        if not isinstance(key, expected_okp):
            curve = "an Ed25519 or Ed448" if alg == "EdDSA" else f"an {alg}"
            raise ValueError(f"{alg} requires {curve} {role} key, got {type(key).__name__}")
        return
    # Should be unreachable — guarded by the caller's alg check.
    raise ValueError(f"Unsupported asymmetric algorithm: {alg}")


def _sign_with_private_key(private_key, message: bytes, alg: str) -> bytes:
    if alg in OKP_ALGORITHMS:
        # EdDSA hashes internally and emits the raw RFC 8032 signature.
        return private_key.sign(message)
    hash_alg = _HASH_BY_ALG[alg]()
    if alg in RSA_ALGORITHMS:
        return private_key.sign(message, padding.PKCS1v15(), hash_alg)
    if alg in PSS_ALGORITHMS:
        # PSS salt length per RFC 7518 §3.5: equal to the hash output size.
        return private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH),
            hash_alg,
        )
    # EC — cryptography emits DER; JWS expects raw r || s.
    der_sig = private_key.sign(message, ec.ECDSA(hash_alg))
    return _ec_der_to_raw(der_sig, alg)


def _verify_with_public_key(public_key, message: bytes, raw_sig: bytes, alg: str) -> None:
    if alg in OKP_ALGORITHMS:
        public_key.verify(raw_sig, message)
        return
    hash_alg = _HASH_BY_ALG[alg]()
    if alg in RSA_ALGORITHMS:
        public_key.verify(raw_sig, message, padding.PKCS1v15(), hash_alg)
        return
    if alg in PSS_ALGORITHMS:
        public_key.verify(
            raw_sig,
            message,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH),
            hash_alg,
        )
        return
    # EC — JWS r||s is fixed-width; reject anything else before decoding.
    expected_len = _EC_RAW_SIG_HALF_BYTES[alg] * 2
    if len(raw_sig) != expected_len:
        raise InvalidSignature(
            f"ECDSA signature length {len(raw_sig)} != expected {expected_len} for {alg}"
        )
    der_sig = _ec_raw_to_der(raw_sig, alg)
    public_key.verify(der_sig, message, ec.ECDSA(hash_alg))


def _ec_der_to_raw(der: bytes, alg: str) -> bytes:
    r, s = decode_dss_signature(der)
    half = _EC_RAW_SIG_HALF_BYTES[alg]
    return r.to_bytes(half, "big") + s.to_bytes(half, "big")


def _ec_raw_to_der(raw: bytes, alg: str) -> bytes:
    half = _EC_RAW_SIG_HALF_BYTES[alg]
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return encode_dss_signature(r, s)
