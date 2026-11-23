import binascii
import json
from dataclasses import dataclass

from jwt_toolkit.core.encoding import (
    MAX_JSON_DEPTH,
    DuplicateMemberError,
    JsonObject,
    JsonTooDeepError,
    NonFiniteNumberError,
    base64url_decode,
    base64url_encode,
    strict_json_loads,
)
from jwt_toolkit.core.errors import TokenDecodeError

# Far above real tokens (an ID token with many group claims is tens of KiB), low
# enough that a hostile input cannot make parsing or rendering expensive.
MAX_TOKEN_BYTES = 256 * 1024


@dataclass(frozen=True)
class DecodedToken:
    header: JsonObject
    payload: JsonObject
    signature: str
    header_b64: str
    payload_b64: str
    # True when whitespace inside the token was removed for inspection.
    whitespace_removed: bool = False


def check_token_size(size: int) -> None:
    if size > MAX_TOKEN_BYTES:
        raise TokenDecodeError(
            code="token_too_large",
            title="Invalid Token",
            headline="Token is too large to be a JWT",
            details=(f"The limit is {MAX_TOKEN_BYTES // 1024} KiB",),
        )


def split_token(token: str, *, tolerate_whitespace: bool = False) -> tuple[str, str, str]:
    token = token.strip()
    if any(char.isspace() for char in token):
        if not tolerate_whitespace:
            raise TokenDecodeError(
                code="invalid_structure",
                cause="embedded_whitespace",
                title="Invalid Token",
                headline="Token contains whitespace, so a server would reject it as sent",
                details=(
                    "A JWT has no spaces or line breaks inside it",
                    "The token may have been wrapped or pasted incorrectly",
                ),
            )
        token = "".join(token.split())
    parts = token.split(".")
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


def _bad_base64url(cause: str | None, *details: str) -> TokenDecodeError:
    return TokenDecodeError(
        code="invalid_base64url",
        cause=cause,
        title="Decode Error",
        headline="Token contains invalid base64url encoding",
        details=details,
    )


def _decode_segment(segment: str) -> bytes:
    # RFC 7515 2: JWS base64url omits the '=' padding.
    if "=" in segment:
        raise _bad_base64url(
            "base64url_padding",
            "A token part ends in '=' padding, which a JWT never contains",
        )
    try:
        decoded = base64url_decode(segment)
    except binascii.Error as exc:
        raise _bad_base64url(
            None,
            "One or more parts could not be decoded",
            "The token may be truncated or corrupted",
        ) from exc
    if base64url_encode(decoded) != segment:
        raise _bad_base64url(
            "base64url_noncanonical",
            "A token part has stray bits in its last character",
            "Each part has exactly one valid spelling; this one was altered",
        )
    return decoded


def _invalid_json(cause: str | None, detail: str) -> TokenDecodeError:
    return TokenDecodeError(
        code="invalid_json",
        cause=cause,
        title="Parse Error",
        headline="Token decoded but header or payload is not valid JSON",
        details=(detail,),
    )


def decode_token(token: str, *, tolerate_whitespace: bool = False) -> DecodedToken:
    # Every parse failure surfaces as a TokenDecodeError, so callers have one error
    # type to catch. Whitespace inside the token is only removed when the caller
    # asks for it, for inspection that never verifies.
    check_token_size(len(token.encode("utf-8", errors="surrogatepass")))
    header_b64, payload_b64, signature = split_token(token, tolerate_whitespace=tolerate_whitespace)
    raw_header = _decode_segment(header_b64)
    raw_payload = _decode_segment(payload_b64)
    # The signature is left to the verifier, which reports a malformed one as a
    # failed check, and inspection can still show the token.
    try:
        header = strict_json_loads(raw_header)
        payload = strict_json_loads(raw_payload)
    except UnicodeDecodeError as exc:
        raise _bad_base64url(
            "invalid_utf8",
            "The header or payload is not UTF-8 text",
            "A JWT header and payload are UTF-8 JSON",
        ) from exc
    except NonFiniteNumberError as exc:
        raise TokenDecodeError(
            code="invalid_number",
            title="Parse Error",
            headline="Token contains a non-finite number (NaN or Infinity)",
            details=(
                "JSON does not allow NaN or Infinity, and numbers must not overflow",
                "Time claims with such values cannot be checked",
            ),
        ) from exc
    except DuplicateMemberError as exc:
        raise _invalid_json(
            "duplicate_member",
            "A member name appears twice, so parsers disagree about its value",
        ) from exc
    except JsonTooDeepError as exc:
        raise _invalid_json(
            "json_too_deep", f"The JSON is nested deeper than {MAX_JSON_DEPTH} levels"
        ) from exc
    except json.JSONDecodeError as exc:
        raise _invalid_json(None, f"JSON error : {exc.msg}") from exc
    except ValueError as exc:
        raise _invalid_json(None, "A number in the token could not be parsed") from exc
    return DecodedToken(
        header=_require_object("header", header),
        payload=_require_object("payload", payload),
        signature=signature,
        header_b64=header_b64,
        payload_b64=payload_b64,
        whitespace_removed=any(char.isspace() for char in token.strip()),
    )


def _require_object(label: str, part: object) -> JsonObject:
    # RFC 7515/7519: the protected header and the claims set must be JSON objects.
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
    return part
