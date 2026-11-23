import hmac

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from jwt_toolkit.core.algorithms import (
    ALGORITHMS,
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
    KeyAlgorithmMismatchError,
    KeyParseError,
    KeyPassphraseRequiredError,
    UnsupportedAlgorithmError,
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
    "verify_asymmetric",
    "verify_signature",
]

type _SigningPrivateKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)
type _VerifyingPublicKey = (
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
        raise UnsupportedAlgorithmError(
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


def algorithm_for_private_key(pem: bytes, *, passphrase: bytes | None = None) -> str:
    # The default algorithm for a key: RS256 for RSA, the ES* that RFC 7518 3.4
    # pairs with the curve, and the fully-specified EdDSA name (RFC 9864).
    key = _parse_private_key(pem, passphrase)
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


def _load_private_key(
    pem: bytes, alg: str, *, passphrase: bytes | None = None
) -> _SigningPrivateKey:
    key = _parse_private_key(pem, passphrase)
    _ensure_key_matches_alg(key, alg, is_private=True)
    if not isinstance(key, _SIGNING_PRIVATE_KEY_TYPES):
        raise KeyParseError(f"A {type(key).__name__} cannot sign a JWS")
    return key


def _parse_private_key(pem: bytes, passphrase: bytes | None) -> PrivateKeyTypes:
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


def _load_public_key(pem: bytes, alg: str) -> _VerifyingPublicKey:
    key: PublicKeyTypes
    try:
        if b"-----BEGIN CERTIFICATE-----" in pem:
            # Identity providers often publish signing keys as certificates. The
            # certificate is only a key container here: no chain or validity check.
            key = x509.load_pem_x509_certificate(pem).public_key()
        else:
            key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise KeyParseError(f"Could not parse PEM public key or certificate: {exc}") from exc
    _ensure_key_matches_alg(key, alg, is_private=False)
    if not isinstance(key, _VERIFYING_PUBLIC_KEY_TYPES):
        raise KeyParseError(f"A {type(key).__name__} cannot verify a JWS")
    return key


def _ensure_key_matches_alg(
    key: PrivateKeyTypes | PublicKeyTypes, alg: str, *, is_private: bool
) -> None:
    role = "private" if is_private else "public"
    if alg in RSA_ALGORITHMS or alg in PSS_ALGORITHMS:
        expected = rsa.RSAPrivateKey if is_private else rsa.RSAPublicKey
        if not isinstance(key, expected):
            raise KeyAlgorithmMismatchError(
                f"{alg} requires an RSA {role} key, got {type(key).__name__}"
            )
        return
    if alg in EC_ALGORITHMS:
        if not isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) or (
            isinstance(key, ec.EllipticCurvePrivateKey) is not is_private
        ):
            raise KeyAlgorithmMismatchError(
                f"{alg} requires an EC {role} key, got {type(key).__name__}"
            )
        expected_curve = _spec(alg).curve
        if expected_curve is None or not isinstance(key.curve, expected_curve):
            raise KeyAlgorithmMismatchError(
                f"{alg} requires curve {expected_curve.name if expected_curve else '?'}, "
                f"got {key.curve.name}"
            )
        return
    if alg in OKP_ALGORITHMS:
        spec = _spec(alg)
        expected_okp = spec.okp_private_types if is_private else spec.okp_public_types
        if not isinstance(key, expected_okp):
            curve = "an Ed25519 or Ed448" if alg == "EdDSA" else f"an {alg}"
            raise KeyAlgorithmMismatchError(
                f"{alg} requires {curve} {role} key, got {type(key).__name__}"
            )
        return
    # Unreachable: callers check alg against ASYMMETRIC_ALGORITHMS first.
    raise UnsupportedAlgorithmError(f"Unsupported asymmetric algorithm: {alg}")


def _pss_padding(hash_alg: hashes.HashAlgorithm) -> padding.PSS:
    # RFC 7518 3.5: the PSS salt is as long as the hash output.
    return padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH)


def _sign_with_private_key(private_key: _SigningPrivateKey, message: bytes, alg: str) -> bytes:
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
    public_key: _VerifyingPublicKey, message: bytes, raw_sig: bytes, alg: str
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
