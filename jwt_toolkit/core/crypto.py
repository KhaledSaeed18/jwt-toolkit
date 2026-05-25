import hashlib
import hmac

from jwt_toolkit.core.encoding import base64url_encode

# Crypto module — HMAC signing and verification for HS256/HS384/HS512 tokens.

SUPPORTED_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


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
    # compare_digest is timing-safe — unlike ==, it doesn't short-circuit.
    return hmac.compare_digest(expected, signature)
