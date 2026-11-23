import binascii
import json
import time

import pytest

from jwt_toolkit.core.encoding import (
    MAX_JSON_DEPTH,
    DuplicateMemberError,
    JsonTooDeepError,
    base64_decode_padded,
    base64url_decode,
    base64url_encode,
    strict_json_loads,
)


@pytest.mark.parametrize("raw", [b"", b"i", b"i\xb7", b"i\xb7\x1d", b"\xfb\xff\xbf"])
def test_base64url_round_trip(raw):
    assert base64url_decode(base64url_encode(raw)) == raw


def test_base64url_accepts_trailing_padding():
    assert base64url_decode("abcd===") == b"i\xb7\x1d"
    assert base64url_decode("abc=") == b"i\xb7"


# Python 3.15 decodes these leniently by dropping the stray characters; a JWT
# segment carrying them must be rejected on every supported version.
@pytest.mark.parametrize(
    "value",
    ["ab!c", "@@@not-base64@@@", "ab c", "ab\nc", "abc\n", "ab+c", "ab/c", "a=bc", "abcé", "abcde"],
)
def test_base64url_rejects_input_outside_the_alphabet(value):
    with pytest.raises(binascii.Error):
        base64url_decode(value)


def test_base64_padded_decodes_standard_alphabet():
    assert base64_decode_padded("+/8") == b"\xfb\xff"
    assert base64_decode_padded("+/8=") == b"\xfb\xff"


@pytest.mark.parametrize("value", ["-_8", "ab!c", "ab c", "abcde"])
def test_base64_padded_rejects_input_outside_the_alphabet(value):
    with pytest.raises(binascii.Error):
        base64_decode_padded(value)


def _nested(depth: int) -> str:
    return "[" * (depth - 1) + "{}" + "]" * (depth - 1)


def test_strict_json_accepts_nesting_at_the_limit():
    assert strict_json_loads(_nested(MAX_JSON_DEPTH)) is not None


def test_strict_json_rejects_nesting_above_the_limit():
    with pytest.raises(JsonTooDeepError):
        strict_json_loads(_nested(MAX_JSON_DEPTH + 1))


def test_strict_json_turns_parser_recursion_into_too_deep():
    with pytest.raises(JsonTooDeepError):
        strict_json_loads("[" * 100_000)


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"x":{"a":1,"a":1}}', '[{"a":1,"a":2}]'])
def test_strict_json_rejects_duplicate_members(raw):
    with pytest.raises(DuplicateMemberError):
        strict_json_loads(raw)


def test_strict_json_allows_the_same_name_in_different_objects():
    assert strict_json_loads('{"a":{"a":1},"b":{"a":2}}') == {"a": {"a": 1}, "b": {"a": 2}}


@pytest.mark.parametrize(
    "raw",
    ['{"a":1}'.encode("utf-16"), '{"a":1}'.encode("utf-32-le"), b"\xef\xbb\xbf{}", b'{"a":"\xff"}'],
)
def test_strict_json_requires_utf8_bytes(raw):
    with pytest.raises((UnicodeDecodeError, json.JSONDecodeError)):
        strict_json_loads(raw)


@pytest.mark.parametrize("bracket", ["[", "{", "]", "}"])
def test_brackets_inside_strings_do_not_count_as_nesting(bracket):
    text = '{"a":"' + bracket * 100 + '","b":"\\"' + bracket * 100 + '"}'
    assert strict_json_loads(text) == {"a": bracket * 100, "b": '"' + bracket * 100}


# These made an earlier regex-based depth scan quadratic: minutes at the token limit.
@pytest.mark.parametrize("unit", ['"\\', '\\"', '"a\\', "\\", '"['])
def test_depth_scan_is_linear_on_hostile_text(unit):
    text = unit * (256 * 1024 // len(unit))
    start = time.perf_counter()
    with pytest.raises(ValueError):
        strict_json_loads(text)
    assert time.perf_counter() - start < 2


def test_canonical_decode_rejects_altered_pad_bits():
    # "abc" decodes to 2 bytes plus 2 unused bits; "abd" differs only in those bits.
    assert base64url_decode("abd") == base64url_decode("abc")
    assert base64url_decode("abc", canonical=True) == b"i\xb7"
    with pytest.raises(binascii.Error):
        base64url_decode("abd", canonical=True)
