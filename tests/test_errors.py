import dataclasses
import inspect
import json

import pytest

from jwt_toolkit.core import errors
from jwt_toolkit.core.crypto import sign_asymmetric, verify_asymmetric
from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.errors import JwtToolkitError, redact_url
from jwt_toolkit.core.forge import forge_one
from jwt_toolkit.core.jwks import fetch_jwks, select_jwk
from tests.helpers import make_token


def _error_classes() -> list[type[JwtToolkitError]]:
    return [
        cls
        for _, cls in inspect.getmembers(errors, inspect.isclass)
        if issubclass(cls, JwtToolkitError) and cls is not JwtToolkitError
    ]


def _default_code(cls: type[JwtToolkitError]) -> str:
    return next(f.default for f in dataclasses.fields(cls) if f.name == "code")


def test_every_error_class_has_its_own_code():
    codes = [_default_code(cls) for cls in _error_classes() if cls is not errors.TokenDecodeError]
    assert len(codes) == len(set(codes)), codes
    assert all(code.islower() and " " not in code for code in codes)


def test_errors_are_value_errors_for_existing_callers():
    for cls in _error_classes():
        assert issubclass(cls, ValueError)


def test_str_is_the_headline():
    exc = errors.KeyParseError("Could not parse the key", ("detail",))
    assert str(exc) == "Could not parse the key"
    assert exc.code == "key_parse_failed"
    assert exc.title == "Key Error"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://user:pass@idp.example/jwks?token=abc#frag", "https://idp.example/jwks"),
        (
            "https://idp.example:8443/.well-known/jwks.json",
            "https://idp.example:8443/.well-known/jwks.json",
        ),
        ("http://[::1]:8080/jwks?k=v", "http://[::1]:8080/jwks"),
        ("file:///tmp/jwks.json", "file:///tmp/jwks.json"),
        ("https://idp.example:notaport/x", "<unparseable URL>"),
    ],
)
def test_redact_url(url, expected):
    assert redact_url(url) == expected


def test_crypto_raises_typed_key_errors(rsa_keypair, ec_p256_keypair):
    with pytest.raises(errors.KeyParseError):
        sign_asymmetric("e30", "e30", b"not a key", "RS256")
    with pytest.raises(errors.KeyAlgorithmMismatchError):
        sign_asymmetric("e30", "e30", ec_p256_keypair.private_pem, "RS256")
    with pytest.raises(errors.UnsupportedAlgorithmError):
        verify_asymmetric("e30", "e30", "sig", rsa_keypair.public_pem, "HS256")


def test_forge_raises_typed_errors(rsa_keypair):
    decoded = decode_token(make_token({"sub": "1"}))
    with pytest.raises(errors.ForgeVariantUnknownError):
        forge_one("no_such_variant", decoded)
    with pytest.raises(errors.ForgeVariantNeedsKeyError):
        forge_one("hs_rs_confusion", decoded)
    with pytest.raises(errors.KeyNotPublicError):
        forge_one("hs_rs_confusion", decoded, public_key_pem=rsa_keypair.private_pem)


def test_jwks_selection_errors_are_typed():
    one = {"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB"}
    with pytest.raises(errors.JwksInvalidError):
        select_jwk({"keys": []}, kid=None, alg="RS256")
    with pytest.raises(errors.JwksNoMatchingKeyError):
        select_jwk({"keys": [one]}, kid="missing", alg="RS256")
    with pytest.raises(errors.JwksAmbiguousError):
        select_jwk({"keys": [one, one]}, kid="a", alg="RS256")
    with pytest.raises(errors.JwksAmbiguousError):
        select_jwk({"keys": [one, {**one, "kid": "b"}]}, kid=None, alg="RS256")
    with pytest.raises(errors.KeyAlgorithmMismatchError):
        select_jwk({"keys": [one]}, kid="a", alg="ES256")


def test_jwks_fetch_errors_never_echo_credentials(tmp_path):
    with pytest.raises(errors.JwksFetchError) as excinfo:
        fetch_jwks("ftp://user:hunter2@idp.example/jwks?api_key=SEKRET")
    message = str(excinfo.value)
    assert "hunter2" not in message
    assert "SEKRET" not in message

    missing = tmp_path / "nope.json"
    with pytest.raises(errors.JwksFetchError):
        fetch_jwks(missing.as_uri())

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not_keys": []}))
    with pytest.raises(errors.JwksInvalidError):
        fetch_jwks(bad.as_uri())
