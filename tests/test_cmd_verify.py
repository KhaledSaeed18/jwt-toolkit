import json
import time

import pytest
from cryptography.hazmat.primitives import serialization as _s
from cryptography.hazmat.primitives.asymmetric import rsa

from jwt_toolkit.cli import cli
from jwt_toolkit.core.crypto import sign_asymmetric
from jwt_toolkit.core.encoding import base64url_encode
from tests.helpers import make_rs256_token, make_token, make_unsigned_token


def _asymmetric_token(payload: dict, alg: str, private_pem: bytes) -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign_asymmetric(h, p, private_pem, alg)
    return f"{h}.{p}.{sig}"


def invoke(runner, *args):
    return runner.invoke(cli, ["verify", *args])


# Signature verification


def test_valid_signature_exits_0(runner, valid_token):
    result = invoke(runner, valid_token, "--secret", "testsecret")
    assert result.exit_code == 0


def test_wrong_secret_exits_1(runner, valid_token):
    result = invoke(runner, valid_token, "--secret", "wrongsecret")
    assert result.exit_code == 1


# Algorithm rejection


def test_alg_none_exits_2(runner):
    t = make_unsigned_token({"sub": "1"})
    result = invoke(runner, t, "--secret", "any")
    assert result.exit_code == 2


def test_rs256_exits_2(runner):
    t = make_rs256_token({"sub": "1"})
    result = invoke(runner, t, "--secret", "any")
    assert result.exit_code == 2


# Temporal claim checks


def test_expired_token_exits_1(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) - 3600})
    result = invoke(runner, t, "--secret", "testsecret")
    assert result.exit_code == 1
    assert "expired" in result.output.lower()


def test_valid_exp_exits_0(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) + 3600})
    result = invoke(runner, t, "--secret", "testsecret")
    assert result.exit_code == 0


def test_leeway_rescues_just_expired_token(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) - 5})
    without = invoke(runner, t, "--secret", "testsecret")
    with_leeway = invoke(runner, t, "--secret", "testsecret", "--leeway", "60")
    assert without.exit_code == 1
    assert with_leeway.exit_code == 0


# Issuer and audience


def test_issuer_match_passes(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) + 3600, "iss": "auth.example.com"})
    result = invoke(runner, t, "--secret", "testsecret", "--issuer", "auth.example.com")
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_issuer_mismatch_exits_1(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) + 3600, "iss": "real.issuer"})
    result = invoke(runner, t, "--secret", "testsecret", "--issuer", "evil.issuer")
    assert result.exit_code == 1


def test_audience_match_passes(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) + 3600, "aud": "myapp"})
    result = invoke(runner, t, "--secret", "testsecret", "--audience", "myapp")
    assert result.exit_code == 0


def test_audience_mismatch_exits_1(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) + 3600, "aud": "myapp"})
    result = invoke(runner, t, "--secret", "testsecret", "--audience", "otherapp")
    assert result.exit_code == 1


# --json output


def test_json_output_valid(runner, valid_token):
    result = invoke(runner, valid_token, "--secret", "testsecret", "--json")
    data = json.loads(result.output)
    assert data["valid"] is True
    assert isinstance(data["checks"], list)
    assert data["schema_version"] == "0.1"


def test_json_output_invalid(runner, valid_token):
    result = invoke(runner, valid_token, "--secret", "wrongsecret", "--json")
    data = json.loads(result.output)
    assert data["valid"] is False
    sig_check = next(c for c in data["checks"] if c["check"] == "signature")
    assert sig_check["result"] == "FAIL"


# Malformed token


def test_malformed_token_exits_2(runner):
    result = invoke(runner, "a.b", "--secret", "s")
    assert result.exit_code == 2


# Asymmetric verification


@pytest.mark.parametrize(
    "alg",
    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
)
def test_asymmetric_valid_signature_exits_0(runner, tmp_path, keypair_for, alg):
    kp = keypair_for(alg)
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    token = _asymmetric_token({"sub": "1", "exp": 9999999999}, alg, kp.private_pem)
    result = invoke(runner, token, "--public-key", str(pub))
    assert result.exit_code == 0, result.output


def test_asymmetric_wrong_public_key_exits_1(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    # Sign with one RSA key, verify with a different one.
    other = rsa.generate_private_key(65537, 2048)
    other_pub = other.public_key().public_bytes(
        _s.Encoding.PEM, _s.PublicFormat.SubjectPublicKeyInfo
    )
    pub = tmp_path / "pub.pem"
    pub.write_bytes(other_pub)
    token = _asymmetric_token({"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem)
    result = invoke(runner, token, "--public-key", str(pub))
    assert result.exit_code == 1


def test_asymmetric_alg_with_secret_exits_2(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    token = _asymmetric_token({"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem)
    result = invoke(runner, token, "--secret", "anything")
    assert result.exit_code == 2


def test_hmac_alg_with_public_key_exits_2(runner, tmp_path, keypair_for, valid_token):
    kp = keypair_for("RS256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    # HS256 token but --public-key supplied.
    result = invoke(runner, valid_token, "--public-key", str(pub))
    assert result.exit_code == 2


def test_asymmetric_token_without_any_key_exits_2(runner, keypair_for):
    kp = keypair_for("RS256")
    token = _asymmetric_token({"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem)
    result = invoke(runner, token)
    assert result.exit_code == 2


def test_asymmetric_tampered_payload_exits_1(runner, tmp_path, keypair_for):
    kp = keypair_for("ES256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    token = _asymmetric_token({"sub": "1", "exp": 9999999999}, "ES256", kp.private_pem)
    # Swap the payload segment for a different (still well-formed) one.
    header_b64, _payload_b64, sig = token.split(".")
    tampered_payload = base64url_encode(b'{"sub":"attacker","exp":9999999999}')
    tampered = f"{header_b64}.{tampered_payload}.{sig}"
    result = invoke(runner, tampered, "--public-key", str(pub))
    assert result.exit_code == 1


def test_asymmetric_curve_mismatch_exits_2(runner, tmp_path, keypair_for):
    # Token claims ES256 but we provide a P-384 public key — key/alg mismatch.
    es256_kp = keypair_for("ES256")
    es384_kp = keypair_for("ES384")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(es384_kp.public_pem)
    token = _asymmetric_token({"sub": "1", "exp": 9999999999}, "ES256", es256_kp.private_pem)
    result = invoke(runner, token, "--public-key", str(pub))
    assert result.exit_code == 2
