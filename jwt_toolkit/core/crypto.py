import hmac
import hashlib
import base64

# Crypto module to handle signing and verifying JWT tokens using HMAC with various hashing algorithms (HS256, HS384, HS512).

# Define a mapping of supported algorithms to their corresponding hashlib functions for HMAC signing and verification.
SUPPORTED_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# Function to perform base64url encoding, which is used for encoding the signature in JWT tokens, ensuring that the output is URL-safe and does not include padding characters.
def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

# Function to sign a JWT token using the specified header and payload (both base64url-encoded), a secret key, and the chosen algorithm. The function generates the signature by creating an HMAC digest of the header and payload using the secret key and the appropriate hashing algorithm.
def sign(header_b64: str, payload_b64: str, secret: str, alg: str = "HS256") -> str:
    digestmod = SUPPORTED_ALGORITHMS.get(alg.upper())
    if digestmod is None:
        raise ValueError(f"Unsupported algorithm: {alg}. Supported: {', '.join(SUPPORTED_ALGORITHMS)}")
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), message, digestmod).digest()
    return base64url_encode(signature)

# Function to verify the signature of a JWT token by comparing the expected signature (generated using the same header, payload, secret, and algorithm) with the provided signature in a way that is resistant to timing attacks using hmac.compare_digest.
def verify_signature(header_b64: str, payload_b64: str, signature: str, secret: str, alg: str = "HS256") -> bool:
    expected = sign(header_b64, payload_b64, secret, alg)
    return hmac.compare_digest(expected, signature)
