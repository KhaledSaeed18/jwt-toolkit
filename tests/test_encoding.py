import binascii

import pytest

from jwt_toolkit.core.encoding import base64_decode_padded, base64url_decode, base64url_encode


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
