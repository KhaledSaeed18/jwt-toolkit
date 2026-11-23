"""The core verification pipeline, exercised without Click and with a frozen clock."""

import json

import pytest

from jwt_toolkit.core.claims import Check
from jwt_toolkit.core.crypto import sign_asymmetric
from jwt_toolkit.core.decoder import decode_token
from jwt_toolkit.core.encoding import base64url_encode
from jwt_toolkit.core.errors import JwksNoMatchingKeyError
from jwt_toolkit.core.keys import HmacKey, load_public_key
from jwt_toolkit.core.verifier import (
    SIGNATURE_INVALID,
    SIGNATURE_VALID,
    Expectations,
    check_signature,
    verify_token,
)
from tests.helpers import TEST_SECRET, make_token

NOW = 1_700_000_000.0
SECRET = HmacKey.from_text(TEST_SECRET)


def _rs256(payload: dict, private_pem: bytes, **header) -> str:
    h = base64url_encode(json.dumps({"alg": "RS256", "typ": "JWT", **header}).encode())
    p = base64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}.{sign_asymmetric(h, p, private_pem, 'RS256')}"


def _by_check(result) -> dict:
    return {c.check: c for c in result.checks}


def test_valid_hmac_token_passes_every_check():
    decoded = decode_token(make_token({"sub": "1", "exp": NOW + 60, "iat": NOW - 1}))
    result = verify_token(decoded, key=SECRET, now=NOW)
    assert result.valid
    assert result.checks[0].check == "signature"
    assert result.checks[0].detail == SIGNATURE_VALID


def test_wrong_secret_fails_the_signature():
    decoded = decode_token(make_token({"sub": "1"}))
    check = check_signature(decoded, HmacKey(b"another-secret"))
    assert (check.result, check.detail) == ("FAIL", SIGNATURE_INVALID)


def test_asymmetric_token_verifies_with_its_public_key(rsa_keypair):
    decoded = decode_token(_rs256({"sub": "1"}, rsa_keypair.private_pem))
    assert check_signature(decoded, load_public_key(rsa_keypair.public_pem)).result == "PASS"


@pytest.mark.parametrize(
    ("header", "fragment"),
    [
        ({"alg": "none"}, "alg: none"),
        ({"alg": "hs256"}, "Unsupported algorithm"),
        ({"typ": "JWT"}, "Unsupported algorithm"),
    ],
)
def test_unacceptable_alg_is_a_failed_check_not_an_error(header, fragment):
    decoded = decode_token(make_token({"sub": "1"}, header_override=header))
    check = check_signature(decoded, SECRET)
    assert check.result == "FAIL"
    assert fragment in check.detail


def test_rs256_token_with_a_secret_is_rejected(rsa_keypair):
    decoded = decode_token(_rs256({"sub": "1"}, rsa_keypair.private_pem))
    check = check_signature(decoded, SECRET)
    assert check.result == "FAIL"
    assert "the key decides the algorithm" in check.detail


def test_hs256_token_with_a_public_key_is_algorithm_confusion(rsa_keypair):
    decoded = decode_token(make_token({"sub": "1"}))
    check = check_signature(decoded, load_public_key(rsa_keypair.public_pem))
    assert check.result == "FAIL"
    assert "CVE-2016-10555" in check.detail


def test_resolver_runs_only_after_the_alg_is_accepted(rsa_keypair):
    calls = []

    def resolver(decoded, spec):
        calls.append(spec.name)
        return load_public_key(rsa_keypair.public_pem)

    rejected = decode_token(make_token({"sub": "1"}))
    assert check_signature(rejected, resolver).result == "FAIL"
    assert calls == []
    accepted = decode_token(_rs256({"sub": "1"}, rsa_keypair.private_pem, kid="k1"))
    assert check_signature(accepted, resolver).result == "PASS"
    assert calls == ["RS256"]


def test_resolver_errors_propagate(rsa_keypair):
    def resolver(decoded, spec):
        raise JwksNoMatchingKeyError("No JWKS key matches kid='x'")

    decoded = decode_token(_rs256({"sub": "1"}, rsa_keypair.private_pem))
    with pytest.raises(JwksNoMatchingKeyError):
        check_signature(decoded, resolver)


def test_frozen_clock_drives_every_time_check():
    decoded = decode_token(make_token({"sub": "1", "exp": NOW - 1, "nbf": NOW + 100}))
    checks = _by_check(verify_token(decoded, key=SECRET, now=NOW))
    assert checks["exp"].result == "FAIL"
    assert checks["nbf"].result == "FAIL"
    later = verify_token(decoded, key=SECRET, now=NOW + 200, expected=Expectations(leeway=0))
    # A satisfied nbf adds no check; only the expired exp remains.
    assert "nbf" not in _by_check(later)
    assert _by_check(later)["exp"].result == "FAIL"


def test_leeway_tolerates_clock_skew():
    decoded = decode_token(make_token({"sub": "1", "exp": NOW - 5}))
    assert _by_check(verify_token(decoded, key=SECRET, now=NOW))["exp"].result == "FAIL"
    tolerant = verify_token(decoded, key=SECRET, now=NOW, expected=Expectations(leeway=10))
    assert _by_check(tolerant)["exp"].result == "PASS"


def test_issuer_and_audience_expectations():
    decoded = decode_token(make_token({"sub": "1", "iss": "https://idp", "aud": ["api"]}))
    good = verify_token(
        decoded, key=SECRET, now=NOW, expected=Expectations(issuer="https://idp", audience="api")
    )
    assert good.valid
    bad = verify_token(decoded, key=SECRET, now=NOW, expected=Expectations(issuer="https://evil"))
    assert not bad.valid
    assert _by_check(bad)["iss"].result == "FAIL"


def test_key_checks_follow_the_signature():
    warning = Check("WARN", "jwks", "fetched over plain HTTP")
    decoded = decode_token(make_token({"sub": "1"}))
    result = verify_token(decoded, key=SECRET, now=NOW, key_checks=[warning])
    assert [c.check for c in result.checks[:2]] == ["signature", "jwks"]
    assert result.valid


def test_critical_headers_are_rejected():
    decoded = decode_token(
        make_token({"sub": "1"}, header_override={"alg": "HS256", "crit": ["x"], "x": 1})
    )
    assert not verify_token(decoded, key=SECRET, now=NOW).valid
