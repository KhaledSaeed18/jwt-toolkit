import base64
import json

# Decoder module to handle splitting and decoding of JWT tokens into their components.

# Splits a JWT token into its header, payload, and signature components.
def split_token(token: str) -> tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 parts, got {len(parts)}")
    return parts[0], parts[1], parts[2]

# Decodes a base64url-encoded string + adding necessary padding if required.
def base64url_decode(value: str) -> bytes:
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return base64.urlsafe_b64decode(value)

# Decodes a JWT token and returns its header, payload, and signature as a tuple.
def decode_token(token: str) -> tuple[dict, dict, str]:
    header_b64, payload_b64, signature = split_token(token)
    header = json.loads(base64url_decode(header_b64))
    payload = json.loads(base64url_decode(payload_b64))
    return header, payload, signature
