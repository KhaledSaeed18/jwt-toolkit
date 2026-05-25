import json

import pytest

from jwt_toolkit.core.crypto import sign, verify_signature
from jwt_toolkit.core.encoding import base64url_encode


def _parts(payload: dict, secret: str, alg: str):
    header = {"alg": alg, "typ": "JWT"}
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign(h, p, secret, alg)
    return h, p, sig


# All algorithm paths sign and verify correctly


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_sign_verify_roundtrip(alg):
    h, p, sig = _parts({"sub": "1"}, "mysecret", alg)
    assert verify_signature(h, p, sig, "mysecret", alg) is True


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_wrong_secret_fails_verification(alg):
    h, p, sig = _parts({"sub": "1"}, "correct", alg)
    assert verify_signature(h, p, sig, "wrong", alg) is False


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_tampered_payload_fails_verification(alg):
    h, _p, sig = _parts({"sub": "1"}, "secret", alg)
    p_tampered = base64url_encode(b'{"sub":"attacker"}')
    assert verify_signature(h, p_tampered, sig, "secret", alg) is False


def test_sign_unsupported_algorithm_raises():
    h = base64url_encode(b'{"alg":"RS256"}')
    p = base64url_encode(b"{}")
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        sign(h, p, "secret", "RS256")


def test_different_algorithms_produce_different_signatures():
    h = base64url_encode(b'{"alg":"HS256"}')
    p = base64url_encode(b'{"sub":"1"}')
    sig256 = sign(h, p, "secret", "HS256")
    sig512 = sign(h, p, "secret", "HS512")
    assert sig256 != sig512
