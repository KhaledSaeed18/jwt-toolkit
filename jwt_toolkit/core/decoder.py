import binascii
import json
from dataclasses import dataclass

from jwt_toolkit.core.encoding import base64url_decode
from jwt_toolkit.core.errors import TokenDecodeError

# Decoder module — splits a JWT and base64url-decodes its header and payload.


@dataclass(frozen=True)
class DecodedToken:
    header: dict
    payload: dict
    signature: str
    header_b64: str
    payload_b64: str


def split_token(token: str) -> tuple[str, str, str]:
    parts = "".join(token.split()).split(".")
    if len(parts) != 3:
        raise TokenDecodeError(
            code="invalid_structure",
            title="Invalid Token",
            headline=f"Invalid JWT structure: expected 3 parts, got {len(parts)}",
            details=(
                "A JWT must have exactly 3 base64url parts separated by dots",
                "Format : <header>.<payload>.<signature>",
            ),
        )
    return parts[0], parts[1], parts[2]


def decode_token(token: str) -> DecodedToken:
    # Surfaces parse failures as TokenDecodeError so the CLI layer has a single
    # error type to catch — no more juggling binascii/json/ValueError everywhere.
    header_b64, payload_b64, signature = split_token(token)
    try:
        header = json.loads(base64url_decode(header_b64))
        payload = json.loads(base64url_decode(payload_b64))
    except (binascii.Error, UnicodeDecodeError) as exc:
        # binascii.Error: bad base64 bytes. UnicodeDecodeError: decoded bytes
        # are not valid UTF-8 and therefore cannot be JSON.
        raise TokenDecodeError(
            code="invalid_base64url",
            title="Decode Error",
            headline="Token contains invalid base64url encoding",
            details=(
                "One or more parts could not be decoded",
                "The token may be truncated or corrupted",
            ),
        ) from exc
    except json.JSONDecodeError as exc:
        raise TokenDecodeError(
            code="invalid_json",
            title="Parse Error",
            headline="Token decoded but header or payload is not valid JSON",
            details=(
                f"JSON error : {exc.msg}",
                "The token structure may be corrupted",
            ),
        ) from exc
    # RFC 7515/7519: the protected header and the claims set must be JSON objects.
    for label, part in (("header", header), ("payload", payload)):
        if not isinstance(part, dict):
            raise TokenDecodeError(
                code="invalid_json_object",
                title="Parse Error",
                headline=f"Token {label} is valid JSON but not a JSON object",
                details=(
                    f"Decoded {label} type : {type(part).__name__}",
                    "A JWT header and payload must each be a JSON object",
                ),
            )
    return DecodedToken(
        header=header,
        payload=payload,
        signature=signature,
        header_b64=header_b64,
        payload_b64=payload_b64,
    )
