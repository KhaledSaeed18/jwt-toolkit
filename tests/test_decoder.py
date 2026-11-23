import base64

import pytest

from jwt_toolkit.core.decoder import MAX_TOKEN_BYTES, decode_token, split_token
from jwt_toolkit.core.encoding import MAX_JSON_DEPTH
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


@pytest.mark.parametrize("value", ["[]", "null", '"text"', "true", "42"])
@pytest.mark.parametrize("part", ["header", "payload"])
def test_non_object_part_raises_decode_error(part, value):
    obj = _b64('{"alg":"HS256"}')
    header, payload = (_b64(value), obj) if part == "header" else (obj, _b64(value))
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(f"{header}.{payload}.sig")
    assert exc.value.code == "invalid_json_object"
    assert part in exc.value.headline


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e400", "-1e400"])
def test_non_finite_number_raises_decode_error(number):
    bad = f"{_b64('{"alg":"HS256"}')}.{_b64('{"exp":' + number + '}')}.sig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(bad)
    assert exc.value.code == "invalid_number"


def test_integer_past_digit_limit_raises_decode_error():
    bad = f"{_b64('{"alg":"HS256"}')}.{_b64('{"exp":' + '9' * 5000 + '}')}.sig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(bad)
    assert exc.value.code == "invalid_json"


def test_fractional_numeric_date_is_preserved():
    t = make_token({"exp": 1700000000.5})
    assert decode_token(t).payload["exp"] == 1700000000.5


def test_deeply_nested_json_raises_decode_error():
    # Deep enough for the parser's own recursion limit, small enough for the size limit.
    deep = base64.urlsafe_b64encode(b"[" * 100_000).rstrip(b"=").decode()
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(f"{deep}.{_b64('{}')}.sig")
    assert exc.value.code == "invalid_json"
    assert exc.value.cause == "json_too_deep"


def test_non_ascii_part_raises_invalid_base64url():
    with pytest.raises(TokenDecodeError) as excinfo:
        decode_token("eyJé.e30.sig")
    assert excinfo.value.code == "invalid_base64url"


def _token_of_length(length: int) -> str:
    head = f"{_b64('{"alg":"HS256"}')}.{_b64('{}')}."
    return head + "A" * (length - len(head))


@pytest.mark.parametrize("length", [MAX_TOKEN_BYTES - 1, MAX_TOKEN_BYTES])
def test_token_at_or_below_the_size_limit_decodes(length):
    assert decode_token(_token_of_length(length)).header == {"alg": "HS256"}


def test_token_above_the_size_limit_is_rejected():
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(_token_of_length(MAX_TOKEN_BYTES + 1))
    assert exc.value.code == "token_too_large"


def test_size_limit_counts_utf8_bytes_not_characters():
    token = _token_of_length(MAX_TOKEN_BYTES - 1) + "é"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(token)
    assert exc.value.code == "token_too_large"


@pytest.mark.parametrize("part", [0, 1])
def test_padded_segment_is_rejected(part):
    parts = make_token({"sub": "1"}).split(".")
    parts[part] += "=" * (-len(parts[part]) % 4 or 4)
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(".".join(parts))
    assert (exc.value.code, exc.value.cause) == ("invalid_base64url", "base64url_padding")


@pytest.mark.parametrize("gap", [" ", "\n", "\r\n", "\t"])
def test_embedded_whitespace_is_rejected_by_default(gap):
    token = make_token({"sub": "1"})
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(token[:10] + gap + token[10:])
    assert (exc.value.code, exc.value.cause) == ("invalid_structure", "embedded_whitespace")


def test_embedded_whitespace_is_removed_only_when_tolerated():
    token = make_token({"sub": "1"})
    decoded = decode_token(token[:10] + "\n" + token[10:], tolerate_whitespace=True)
    assert decoded.payload == {"sub": "1"}
    assert decoded.whitespace_removed


def test_surrounding_whitespace_is_not_a_problem():
    decoded = decode_token(f"  {make_token({'sub': '1'})}\n")
    assert decoded.payload == {"sub": "1"}
    assert not decoded.whitespace_removed


def test_duplicate_claim_is_rejected():
    token = f"{_b64('{"alg":"HS256"}')}.{_b64('{"sub":"a","sub":"b"}')}.sig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(token)
    assert (exc.value.code, exc.value.cause) == ("invalid_json", "duplicate_member")


def test_duplicate_header_member_is_rejected():
    token = f"{_b64('{"alg":"none","alg":"HS256"}')}.{_b64('{}')}.sig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(token)
    assert exc.value.cause == "duplicate_member"


def test_nesting_above_the_limit_is_rejected():
    deep = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
    token = f"{_b64('{"alg":"HS256"}')}.{_b64('{"x":' + deep + '}')}.sig"
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(token)
    assert (exc.value.code, exc.value.cause) == ("invalid_json", "json_too_deep")


def test_utf16_payload_is_rejected():
    payload = base64.urlsafe_b64encode('{"a":1}'.encode("utf-16")).rstrip(b"=").decode()
    with pytest.raises(TokenDecodeError) as exc:
        decode_token(f"{_b64('{"alg":"HS256"}')}.{payload}.sig")
    assert (exc.value.code, exc.value.cause) == ("invalid_base64url", "invalid_utf8")
