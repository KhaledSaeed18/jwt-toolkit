import base64
import json

# Decoder module — splits a JWT and base64url-decodes its header and payload.


# Splits a JWT into its three dot-separated parts.
def split_token(token: str) -> tuple[str, str, str]:
    parts = "".join(token.split()).split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 parts, got {len(parts)}")
    return parts[0], parts[1], parts[2]


# Decodes a base64url string, restoring the padding that JWT strips by spec.
def base64url_decode(value: str) -> bytes:
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return base64.urlsafe_b64decode(value)


# Decodes a full JWT and returns the header, payload, and raw signature.
def decode_token(token: str) -> tuple[dict, dict, str]:
    header_b64, payload_b64, signature = split_token(token)
    header = json.loads(base64url_decode(header_b64))
    payload = json.loads(base64url_decode(payload_b64))
    return header, payload, signature
