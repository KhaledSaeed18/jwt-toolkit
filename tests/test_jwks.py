import json

import pytest
from cryptography.hazmat.primitives import serialization

from jwt_toolkit.core.crypto import sign_asymmetric, verify_asymmetric
from jwt_toolkit.core.encoding import base64url_encode
from jwt_toolkit.core.jwks import (
    fetch_jwks,
    jwk_to_public_pem,
    resolve_jwks_key,
    select_jwk,
)

# Helpers — build JWKs from cryptography key objects rather than hard-coding base64.


def _b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8 or 1
    return base64url_encode(n.to_bytes(length, "big"))


def _rsa_jwk(public_key, *, kid: str | None = None, alg: str | None = None) -> dict:
    numbers = public_key.public_numbers()
    jwk = {"kty": "RSA", "n": _b64(numbers.n), "e": _b64(numbers.e)}
    if kid is not None:
        jwk["kid"] = kid
    if alg is not None:
        jwk["alg"] = alg
    return jwk


def _ec_jwk(public_key, *, kid: str | None = None, alg: str | None = None) -> dict:
    numbers = public_key.public_numbers()
    crv_name = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}[
        public_key.curve.name
    ]
    # Each coordinate is fixed-width per RFC 7518 §6.2.1.{2,3}.
    field_bytes = (public_key.curve.key_size + 7) // 8
    jwk = {
        "kty": "EC",
        "crv": crv_name,
        "x": base64url_encode(numbers.x.to_bytes(field_bytes, "big")),
        "y": base64url_encode(numbers.y.to_bytes(field_bytes, "big")),
    }
    if kid is not None:
        jwk["kid"] = kid
    if alg is not None:
        jwk["alg"] = alg
    return jwk


# jwk_to_public_pem — round-trip the PEM back through verify_asymmetric so we
# know the materialised key actually verifies a real signature.


def test_rsa_jwk_to_pem_verifies_real_signature(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwk = _rsa_jwk(public_key)
    pem = jwk_to_public_pem(jwk, "RS256")
    sig = sign_asymmetric("aGVhZA", "cGF5", rsa_keypair.private_pem, "RS256")
    assert verify_asymmetric("aGVhZA", "cGF5", sig, pem, "RS256") is True


@pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
def test_ec_jwk_to_pem_verifies_real_signature(alg, keypair_for):
    kp = keypair_for(alg)
    public_key = serialization.load_pem_public_key(kp.public_pem)
    jwk = _ec_jwk(public_key)
    pem = jwk_to_public_pem(jwk, alg)
    sig = sign_asymmetric("aGVhZA", "cGF5", kp.private_pem, alg)
    assert verify_asymmetric("aGVhZA", "cGF5", sig, pem, alg) is True


def test_jwk_to_pem_rejects_unsupported_alg(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwk = _rsa_jwk(public_key)
    with pytest.raises(ValueError, match="unsupported alg"):
        jwk_to_public_pem(jwk, "HS256")


def test_jwk_to_pem_rejects_kty_mismatch(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwk = _rsa_jwk(public_key)
    # RSA JWK requested for an EC alg — should reject before any crypto runs.
    with pytest.raises(ValueError, match="does not match alg"):
        jwk_to_public_pem(jwk, "ES256")


def test_jwk_to_pem_rejects_crv_mismatch(keypair_for):
    p256 = keypair_for("ES256")
    public_key = serialization.load_pem_public_key(p256.public_pem)
    jwk = _ec_jwk(public_key)  # crv=P-256
    with pytest.raises(ValueError, match="crv"):
        jwk_to_public_pem(jwk, "ES384")


def test_jwk_to_pem_rejects_self_declared_alg_mismatch(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwk = _rsa_jwk(public_key, alg="RS512")
    with pytest.raises(ValueError, match="JWK alg"):
        jwk_to_public_pem(jwk, "RS256")


def test_rsa_jwk_missing_field_raises(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwk = _rsa_jwk(public_key)
    del jwk["n"]
    with pytest.raises(ValueError, match="missing required field"):
        jwk_to_public_pem(jwk, "RS256")


def test_ec_jwk_missing_field_raises(keypair_for):
    kp = keypair_for("ES256")
    public_key = serialization.load_pem_public_key(kp.public_pem)
    jwk = _ec_jwk(public_key)
    del jwk["y"]
    with pytest.raises(ValueError, match="missing required field"):
        jwk_to_public_pem(jwk, "ES256")


# select_jwk — kid selection edge cases


def test_select_jwk_by_matching_kid(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwks = {"keys": [_rsa_jwk(public_key, kid="a"), _rsa_jwk(public_key, kid="b")]}
    selected = select_jwk(jwks, kid="b", alg="RS256")
    assert selected["kid"] == "b"


def test_select_jwk_no_matching_kid_raises(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwks = {"keys": [_rsa_jwk(public_key, kid="a")]}
    with pytest.raises(ValueError, match="No JWKS key matches"):
        select_jwk(jwks, kid="missing", alg="RS256")


def test_select_jwk_duplicate_kid_raises(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwks = {"keys": [_rsa_jwk(public_key, kid="a"), _rsa_jwk(public_key, kid="a")]}
    with pytest.raises(ValueError, match="ambiguous"):
        select_jwk(jwks, kid="a", alg="RS256")


def test_select_jwk_no_kid_with_single_key_succeeds(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwks = {"keys": [_rsa_jwk(public_key)]}
    selected = select_jwk(jwks, kid=None, alg="RS256")
    assert selected["kty"] == "RSA"


def test_select_jwk_no_kid_with_multiple_keys_refuses(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwks = {"keys": [_rsa_jwk(public_key), _rsa_jwk(public_key)]}
    with pytest.raises(ValueError, match="refusing to guess"):
        select_jwk(jwks, kid=None, alg="RS256")


def test_select_jwk_empty_keys_raises():
    with pytest.raises(ValueError, match="no keys"):
        select_jwk({"keys": []}, kid="a", alg="RS256")


def test_select_jwk_kty_mismatch_raises(rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    jwks = {"keys": [_rsa_jwk(public_key, kid="a")]}
    # Token claims ES256 but the only matching key is RSA → mismatch
    with pytest.raises(ValueError, match="does not match alg"):
        select_jwk(jwks, kid="a", alg="ES256")


# fetch_jwks via file://


def _write_jwks(tmp_path, payload) -> str:
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps(payload))
    return jwks_file.as_uri()


def test_fetch_jwks_via_file_url(tmp_path, rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    url = _write_jwks(tmp_path, {"keys": [_rsa_jwk(public_key, kid="k1")]})
    document = fetch_jwks(url)
    assert document["keys"][0]["kid"] == "k1"


def test_fetch_jwks_missing_keys_array_raises(tmp_path):
    url = _write_jwks(tmp_path, {"something": "else"})
    with pytest.raises(ValueError, match="no 'keys' array"):
        fetch_jwks(url)


def test_fetch_jwks_invalid_json_raises(tmp_path):
    jwks_file = tmp_path / "broken.json"
    jwks_file.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        fetch_jwks(jwks_file.as_uri())


def test_fetch_jwks_unreachable_url_raises():
    # Bogus file:// path → urllib raises URLError → normalised to ValueError.
    with pytest.raises(ValueError, match="Could not fetch JWKS"):
        fetch_jwks("file:///nonexistent/jwks.json")


# resolve_jwks_key end-to-end — the function the CLI actually calls


def test_resolve_jwks_key_end_to_end(tmp_path, rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    url = _write_jwks(tmp_path, {"keys": [_rsa_jwk(public_key, kid="k1")]})
    pem = resolve_jwks_key(url, kid="k1", alg="RS256")
    sig = sign_asymmetric("aGVhZA", "cGF5", rsa_keypair.private_pem, "RS256")
    assert verify_asymmetric("aGVhZA", "cGF5", sig, pem, "RS256") is True


def test_resolve_jwks_key_with_unknown_kid_raises(tmp_path, rsa_keypair):
    public_key = serialization.load_pem_public_key(rsa_keypair.public_pem)
    url = _write_jwks(tmp_path, {"keys": [_rsa_jwk(public_key, kid="known")]})
    with pytest.raises(ValueError, match="No JWKS key matches"):
        resolve_jwks_key(url, kid="unknown", alg="RS256")
