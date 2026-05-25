import base64

import pytest

from jwt_toolkit.core.decoder import decode_token, split_token
from jwt_toolkit.core.errors import TokenDecodeError
from tests.helpers import make_token


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


# split_token structure validation


@pytest.mark.parametrize("bad", ["a", "a.b", "a.b.c.d"])
def test_split_wrong_part_count_raises(bad):
    with pytest.raises(TokenDecodeError) as exc:
        split_token(bad)
    assert exc.value.code == "invalid_structure"
    assert exc.value.title == "Invalid Token"
    assert "3 parts" in exc.value.headline


# decode_token content validation


def test_decode_valid_token():
    t = make_token({"sub": "test-user"}, secret="s", alg="HS256")
    decoded = decode_token(t)
    assert decoded.payload["sub"] == "test-user"
    assert decoded.header["alg"] == "HS256"
    assert decoded.signature != ""


def test_non_utf8_bytes_raises_decode_error():
    # Encode raw bytes that are NOT valid UTF-8 as base64url.
    # json.loads will raise UnicodeDecodeError — must be caught as invalid_base64url.
    non_utf8 = base64.urlsafe_b64encode(b"\x9e\x8b\xff").rstrip(b"=").decode()
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(f"{non_utf8}.{non_utf8}.fakesig")
    assert exc.value.code == "invalid_base64url"
    assert exc.value.title == "Decode Error"


def test_invalid_json_payload_raises_parse_error():
    bad = f"{_b64('{ok:true}')}.{_b64('not-json')}.fakesig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(bad)
    assert exc.value.code == "invalid_json"
    assert exc.value.title == "Parse Error"


def test_garbage_header_raises_parse_error():
    bad = f"{_b64('garbage')}.{_b64('{}')}.sig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(bad)
    assert exc.value.code == "invalid_json"


def test_whitespace_wrapped_token_is_handled():
    t = make_token({"sub": "1"})
    decoded = decode_token(f"  \n  {t}  \n  ")
    assert decoded.payload["sub"] == "1"
