import json
import time

import pytest
from cryptography.hazmat.primitives import serialization as _s
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

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


@pytest.mark.parametrize(
    ("header", "payload"),
    [([], {"sub": "1"}), ({"alg": "HS256"}, ["not", "an", "object"])],
)
def test_non_object_header_or_payload_exits_2_without_traceback(runner, header, payload):
    h = base64url_encode(json.dumps(header).encode())
    p = base64url_encode(json.dumps(payload).encode())
    result = invoke(runner, f"{h}.{p}.sig", "--secret", "testsecret", "--json")
    assert result.exit_code == 2
    assert not isinstance(result.exception, AttributeError)
    assert json.loads(result.output)["error"] == "invalid_json_object"


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


# JWKS verification — file:// URL keeps tests offline


def _b64_int(n: int) -> str:
    length = (n.bit_length() + 7) // 8 or 1
    return base64url_encode(n.to_bytes(length, "big"))


def _rsa_jwk_for(public_pem: bytes, *, kid: str | None = None) -> dict:
    pub = load_pem_public_key(public_pem)
    nums = pub.public_numbers()
    jwk = {"kty": "RSA", "n": _b64_int(nums.n), "e": _b64_int(nums.e)}
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def _write_jwks_file(tmp_path, payload) -> str:
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(payload))
    return path.as_uri()


def _asymmetric_token_with_kid(
    payload: dict, alg: str, private_pem: bytes, *, kid: str | None
) -> str:
    header: dict = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign_asymmetric(h, p, private_pem, alg)
    return f"{h}.{p}.{sig}"


def test_jwks_url_with_matching_kid_verifies(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp.public_pem, kid="k1")]})
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid="k1"
    )
    result = invoke(runner, token, "--jwks-url", url)
    assert result.exit_code == 0, result.output


def test_jwks_url_with_wrong_kid_exits_2(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp.public_pem, kid="k1")]})
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid="unknown"
    )
    result = invoke(runner, token, "--jwks-url", url)
    assert result.exit_code == 2


def test_jwks_url_with_no_kid_and_single_key_verifies(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp.public_pem)]})
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid=None
    )
    result = invoke(runner, token, "--jwks-url", url)
    assert result.exit_code == 0, result.output


def test_jwks_url_with_no_kid_and_multiple_keys_exits_2(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    url = _write_jwks_file(
        tmp_path,
        {"keys": [_rsa_jwk_for(kp.public_pem), _rsa_jwk_for(kp.public_pem)]},
    )
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid=None
    )
    result = invoke(runner, token, "--jwks-url", url)
    assert result.exit_code == 2


def test_jwks_url_with_signed_by_other_key_exits_1(runner, tmp_path, keypair_for):
    # JWKS contains key A; token signed by key B but kid points at A → sig fails.
    kp_a = keypair_for("RS256")
    other = rsa.generate_private_key(65537, 2048)
    other_priv = other.private_bytes(_s.Encoding.PEM, _s.PrivateFormat.PKCS8, _s.NoEncryption())
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp_a.public_pem, kid="k1")]})
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", other_priv, kid="k1"
    )
    result = invoke(runner, token, "--jwks-url", url)
    assert result.exit_code == 1


def test_jwks_url_for_hmac_token_exits_2(runner, tmp_path, keypair_for, valid_token):
    kp = keypair_for("RS256")
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp.public_pem)]})
    result = invoke(runner, valid_token, "--jwks-url", url)
    assert result.exit_code == 2


def test_jwks_url_mutually_exclusive_with_secret(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp.public_pem)]})
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid=None
    )
    result = invoke(runner, token, "--jwks-url", url, "--secret", "x")
    assert result.exit_code == 2


def test_jwks_url_mutually_exclusive_with_public_key(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    url = _write_jwks_file(tmp_path, {"keys": [_rsa_jwk_for(kp.public_pem)]})
    pub_file = tmp_path / "pub.pem"
    pub_file.write_bytes(kp.public_pem)
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid=None
    )
    result = invoke(runner, token, "--jwks-url", url, "--public-key", str(pub_file))
    assert result.exit_code == 2


def test_jwks_url_unreachable_exits_2(runner, keypair_for):
    kp = keypair_for("RS256")
    token = _asymmetric_token_with_kid(
        {"sub": "1", "exp": 9999999999}, "RS256", kp.private_pem, kid=None
    )
    result = invoke(runner, token, "--jwks-url", "file:///nonexistent/jwks.json")
    assert result.exit_code == 2


@pytest.mark.parametrize("exp", [float("nan"), float("inf")])
def test_non_finite_exp_is_never_valid(runner, exp):
    t = make_token({"sub": "1", "exp": exp})
    result = invoke(runner, t, "--secret", "testsecret", "--json")
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "invalid_number"


@pytest.mark.parametrize("claim", ["exp", "nbf"])
@pytest.mark.parametrize("value", [True, False])
def test_boolean_time_claim_fails(runner, claim, value):
    t = make_token({"sub": "1", "exp": 9_999_999_999, claim: value})
    result = invoke(runner, t, "--secret", "testsecret", "--json")
    assert result.exit_code == 1
    check = next(c for c in json.loads(result.output)["checks"] if c["check"] == claim)
    assert check["result"] == "FAIL"


def test_token_is_expired_at_exactly_exp(runner, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
    at_exp = make_token({"sub": "1", "exp": 1_700_000_000})
    just_before = make_token({"sub": "1", "exp": 1_700_000_001})
    assert invoke(runner, at_exp, "--secret", "testsecret").exit_code == 1
    assert invoke(runner, just_before, "--secret", "testsecret").exit_code == 0


def test_leeway_extends_exact_expiry_boundary(runner, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_700_000_010.0)
    t = make_token({"sub": "1", "exp": 1_700_000_000})
    assert invoke(runner, t, "--secret", "testsecret", "--leeway", "10").exit_code == 1
    assert invoke(runner, t, "--secret", "testsecret", "--leeway", "11").exit_code == 0


def _crit_token(extra_header: dict) -> str:
    return make_token(
        {"sub": "1", "exp": 9_999_999_999},
        header_override={"alg": "HS256", "typ": "JWT", **extra_header},
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"crit": ["custom"], "custom": True},
        {"crit": ["exp"], "exp": 1},
        {"crit": "custom", "custom": True},
        {"crit": []},
        {"crit": ["custom", "custom"], "custom": True},
        {"crit": [1]},
        {"crit": ["missing"]},
    ],
)
def test_crit_header_is_rejected(runner, extra):
    result = invoke(runner, _crit_token(extra), "--secret", "testsecret", "--json")
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["valid"] is False
    assert any(c["check"] == "crit" and c["result"] == "FAIL" for c in data["checks"])


@pytest.mark.parametrize("b64", [False, "false", None])
def test_unencoded_payload_header_is_rejected(runner, b64):
    result = invoke(runner, _crit_token({"b64": b64}), "--secret", "testsecret", "--json")
    assert result.exit_code == 1
    assert any(c["check"] == "b64" for c in json.loads(result.output)["checks"])


def test_b64_true_is_accepted(runner):
    result = invoke(runner, _crit_token({"b64": True}), "--secret", "testsecret")
    assert result.exit_code == 0
