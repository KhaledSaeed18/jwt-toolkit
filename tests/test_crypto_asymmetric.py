import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from jwt_toolkit.core.crypto import (
    ASYMMETRIC_ALGORITHMS,
    EC_ALGORITHMS,
    PSS_ALGORITHMS,
    RSA_ALGORITHMS,
    sign_asymmetric,
    verify_asymmetric,
)
from jwt_toolkit.core.encoding import base64url_decode, base64url_encode


def _parts(payload: dict, alg: str, private_pem: bytes):
    header = {"alg": alg, "typ": "JWT"}
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign_asymmetric(h, p, private_pem, alg)
    return h, p, sig


# Round-trips


@pytest.mark.parametrize("alg", sorted(ASYMMETRIC_ALGORITHMS))
def test_sign_verify_roundtrip(alg, keypair_for):
    kp = keypair_for(alg)
    h, p, sig = _parts({"sub": "1"}, alg, kp.private_pem)
    assert verify_asymmetric(h, p, sig, kp.public_pem, alg) is True


@pytest.mark.parametrize("alg", sorted(ASYMMETRIC_ALGORITHMS))
def test_tampered_payload_fails_verification(alg, keypair_for):
    kp = keypair_for(alg)
    h, _p, sig = _parts({"sub": "1"}, alg, kp.private_pem)
    p_tampered = base64url_encode(b'{"sub":"attacker"}')
    assert verify_asymmetric(h, p_tampered, sig, kp.public_pem, alg) is False


@pytest.mark.parametrize("alg", sorted(ASYMMETRIC_ALGORITHMS))
def test_wrong_public_key_fails_verification(alg, keypair_for):
    kp = keypair_for(alg)
    # Generate a fresh, unrelated key of the same family for the negative test.
    if alg in RSA_ALGORITHMS or alg in PSS_ALGORITHMS:
        other = rsa.generate_private_key(65537, 2048)
    else:
        curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}[alg]
        other = ec.generate_private_key(curve())
    other_pub = other.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h, p, sig = _parts({"sub": "1"}, alg, kp.private_pem)
    assert verify_asymmetric(h, p, sig, other_pub, alg) is False


# Signature shape — ES* must be raw r||s of fixed width


@pytest.mark.parametrize(
    ("alg", "expected_raw_len"),
    [("ES256", 64), ("ES384", 96), ("ES512", 132)],
)
def test_ec_signature_is_raw_concat_not_der(alg, expected_raw_len, keypair_for):
    kp = keypair_for(alg)
    _h, _p, sig = _parts({"sub": "1"}, alg, kp.private_pem)
    # base64url-decoded signature length should be exactly r||s, not DER.
    assert len(base64url_decode(sig)) == expected_raw_len


# Algorithm-key mismatches surface as ValueError


def test_rs256_with_ec_key_raises(keypair_for):
    kp = keypair_for("ES256")
    with pytest.raises(ValueError, match="requires an RSA"):
        sign_asymmetric("aGVhZA", "cGF5", kp.private_pem, "RS256")


def test_es256_with_rsa_key_raises(keypair_for):
    kp = keypair_for("RS256")
    with pytest.raises(ValueError, match="requires an EC"):
        sign_asymmetric("aGVhZA", "cGF5", kp.private_pem, "ES256")


def test_es384_with_p256_key_raises_curve_mismatch(keypair_for):
    kp_p256 = keypair_for("ES256")
    with pytest.raises(ValueError, match="curve"):
        sign_asymmetric("aGVhZA", "cGF5", kp_p256.private_pem, "ES384")


def test_unsupported_alg_raises():
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        sign_asymmetric("aGVhZA", "cGF5", b"-----BEGIN-----", "HS256")


def test_malformed_pem_raises(keypair_for):
    with pytest.raises(ValueError, match="Could not parse PEM"):
        sign_asymmetric("aGVhZA", "cGF5", b"not a pem", "RS256")


def test_verify_with_malformed_signature_returns_false(keypair_for):
    kp = keypair_for("RS256")
    # Valid base64url but wrong length / random bytes → verification fails, not raises.
    assert verify_asymmetric("aGVhZA", "cGF5", "AAAA", kp.public_pem, "RS256") is False


def test_verify_with_non_base64_signature_returns_false(keypair_for):
    kp = keypair_for("RS256")
    assert verify_asymmetric("aGVhZA", "cGF5", "@@@not-b64@@@", kp.public_pem, "RS256") is False


def test_ec_signature_length_mismatch_returns_false(keypair_for):
    kp = keypair_for("ES256")
    # 64 zero bytes is the right shape but a clearly invalid signature.
    sig_wrong_len = base64url_encode(b"\x00" * 32)  # half the expected length
    assert verify_asymmetric("aGVhZA", "cGF5", sig_wrong_len, kp.public_pem, "ES256") is False


# Family membership sanity


def test_algorithm_constants_are_disjoint():
    assert RSA_ALGORITHMS.isdisjoint(EC_ALGORITHMS)
    assert RSA_ALGORITHMS.isdisjoint(PSS_ALGORITHMS)
    assert EC_ALGORITHMS.isdisjoint(PSS_ALGORITHMS)
    assert ASYMMETRIC_ALGORITHMS == RSA_ALGORITHMS | EC_ALGORITHMS | PSS_ALGORITHMS
