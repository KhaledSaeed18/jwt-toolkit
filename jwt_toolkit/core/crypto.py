import hmac
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from jwt_toolkit.core.algorithms import (
    ALL_SIGNING_ALGORITHMS,
    ASYMMETRIC_ALGORITHMS,
    EC_ALGORITHMS,
    OKP_ALGORITHMS,
    PSS_ALGORITHMS,
    RSA_ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    AlgorithmSpec,
    algorithm_spec,
    canonical_algorithm,
)
from jwt_toolkit.core.encoding import base64url_decode, base64url_encode
from jwt_toolkit.core.errors import (
    UnsupportedAlgorithmError,
)
from jwt_toolkit.core.keys import (
    HmacKey,
    SigningKey,
    SigningPrivateKey,
    VerificationKey,
    VerifyingPublicKey,
    as_private_key,
    default_algorithm_for,
    ensure_key_matches_algorithm,
    load_public_key_for,
    parse_private_key,
)

# The algorithm tables are derived from the registry in core/algorithms.py and
# re-exported here, where callers have always imported them from. Public API.
__all__ = [
    "ALL_SIGNING_ALGORITHMS",
    "ASYMMETRIC_ALGORITHMS",
    "EC_ALGORITHMS",
    "OKP_ALGORITHMS",
    "PSS_ALGORITHMS",
    "RSA_ALGORITHMS",
    "SUPPORTED_ALGORITHMS",
    "algorithm_for_private_key",
    "canonical_algorithm",
    "sign",
    "sign_asymmetric",
    "sign_with_key",
    "verify_asymmetric",
    "verify_signature",
    "verify_with_key",
]


def _spec(alg: str) -> AlgorithmSpec:
    spec = algorithm_spec(alg)
    if spec is None:
        raise UnsupportedAlgorithmError(f"Unsupported algorithm: {alg}")
    return spec


def _hash(alg: str) -> hashes.HashAlgorithm:
    factory = _spec(alg).hash
    if factory is None:
        raise UnsupportedAlgorithmError(f"{alg} does not use a separate hash")
    return factory()


def _ec_component_bytes(alg: str) -> int:
    size = _spec(alg).ec_component_bytes
    if size is None:
        raise UnsupportedAlgorithmError(f"{alg} is not an ECDSA algorithm")
    return size


def sign(header_b64: str, payload_b64: str, secret: str, alg: str = "HS256") -> str:
    digestmod = SUPPORTED_ALGORITHMS.get(alg.upper())
    if digestmod is None:
        raise UnsupportedAlgorithmError(
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
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {alg}. "
            f"Asymmetric algorithms: {', '.join(sorted(ASYMMETRIC_ALGORITHMS))}"
        )
    raw = parse_private_key(private_key_pem, passphrase)
    ensure_key_matches_algorithm(raw, alg, is_private=True)
    key = as_private_key(raw)
    message = f"{header_b64}.{payload_b64}".encode()
    return base64url_encode(sign_with_key(message, key, _spec(alg)))


def verify_asymmetric(
    header_b64: str,
    payload_b64: str,
    signature: str,
    public_key_pem: bytes,
    alg: str,
) -> bool:
    alg = canonical_algorithm(alg) or alg
    if alg not in ASYMMETRIC_ALGORITHMS:
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm: {alg}. "
            f"Asymmetric algorithms: {', '.join(sorted(ASYMMETRIC_ALGORITHMS))}"
        )
    key = load_public_key_for(public_key_pem, _spec(alg))
    message = f"{header_b64}.{payload_b64}".encode()
    return verify_with_key(message, signature, key, _spec(alg))


def algorithm_for_private_key(pem: bytes, *, passphrase: bytes | None = None) -> str:
    # The default algorithm for a key: RS256 for RSA, the ES* that RFC 7518 3.4
    # pairs with the curve, and the fully-specified EdDSA name (RFC 9864).
    return default_algorithm_for(parse_private_key(pem, passphrase))


def sign_with_key(message: bytes, key: SigningKey, spec: AlgorithmSpec) -> bytes:
    # The raw JWS signature over `message` (header_b64 "." payload_b64).
    key.check_algorithm(spec)
    if isinstance(key, HmacKey):
        return hmac.new(key.secret, message, _hmac_digest(spec)).digest()
    return _sign_with_private_key(key.key, message, spec.name)


def verify_with_key(
    message: bytes, signature: str, key: VerificationKey, spec: AlgorithmSpec
) -> bool:
    # True only when `signature` (the token's base64url segment) is a valid
    # signature over `message` by `key` with `spec`. The key must allow the
    # algorithm; a mismatch raises instead of returning False.
    key.check_algorithm(spec)
    if isinstance(key, HmacKey):
        expected = base64url_encode(hmac.new(key.secret, message, _hmac_digest(spec)).digest())
        # compare_digest is timing-safe. It only accepts ASCII str, and the signature
        # segment comes from the token unvalidated, so both sides are compared as bytes.
        return hmac.compare_digest(expected.encode(), signature.encode("utf-8", "surrogatepass"))
    try:
        raw_sig = base64url_decode(signature)
    except (ValueError, TypeError):
        return False
    try:
        _verify_with_public_key(key.key, message, raw_sig, spec.name)
    except (InvalidSignature, ValueError):
        return False
    return True


def _hmac_digest(spec: AlgorithmSpec) -> Callable[..., Any]:
    if spec.hmac_digest is None:
        raise UnsupportedAlgorithmError(f"{spec.name} is not an HMAC algorithm")
    return spec.hmac_digest


def _pss_padding(hash_alg: hashes.HashAlgorithm) -> padding.PSS:
    # RFC 7518 3.5: the PSS salt is as long as the hash output.
    return padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH)


def _sign_with_private_key(private_key: SigningPrivateKey, message: bytes, alg: str) -> bytes:
    if isinstance(private_key, ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey):
        # EdDSA hashes internally and emits the raw RFC 8032 signature.
        return private_key.sign(message)
    hash_alg = _hash(alg)
    if isinstance(private_key, rsa.RSAPrivateKey):
        pad = _pss_padding(hash_alg) if alg in PSS_ALGORITHMS else padding.PKCS1v15()
        return private_key.sign(message, pad, hash_alg)
    # cryptography emits DER; JWS expects the raw r || s.
    der_sig = private_key.sign(message, ec.ECDSA(hash_alg))
    return _ec_der_to_raw(der_sig, alg)


def _verify_with_public_key(
    public_key: VerifyingPublicKey, message: bytes, raw_sig: bytes, alg: str
) -> None:
    if isinstance(public_key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        public_key.verify(raw_sig, message)
        return
    hash_alg = _hash(alg)
    if isinstance(public_key, rsa.RSAPublicKey):
        pad = _pss_padding(hash_alg) if alg in PSS_ALGORITHMS else padding.PKCS1v15()
        public_key.verify(raw_sig, message, pad, hash_alg)
        return
    # JWS r || s is fixed-width; reject anything else before decoding.
    expected_len = _ec_component_bytes(alg) * 2
    if len(raw_sig) != expected_len:
        raise InvalidSignature(
            f"ECDSA signature length {len(raw_sig)} != expected {expected_len} for {alg}"
        )
    der_sig = _ec_raw_to_der(raw_sig, alg)
    public_key.verify(der_sig, message, ec.ECDSA(hash_alg))


def _ec_der_to_raw(der: bytes, alg: str) -> bytes:
    r, s = decode_dss_signature(der)
    half = _ec_component_bytes(alg)
    return r.to_bytes(half, "big") + s.to_bytes(half, "big")


def _ec_raw_to_der(raw: bytes, alg: str) -> bytes:
    half = _ec_component_bytes(alg)
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return encode_dss_signature(r, s)
