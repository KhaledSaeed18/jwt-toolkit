import json
import time

from cryptography.hazmat.primitives import serialization as _s
from cryptography.hazmat.primitives.asymmetric import rsa

from jwt_toolkit.cli import cli
from jwt_toolkit.core.crypto import sign_asymmetric
from jwt_toolkit.core.encoding import base64url_encode
from tests.helpers import make_token, make_unsigned_token


def invoke(runner, *args):
    return runner.invoke(cli, ["audit", *args])


# Basic audit


def test_audit_insecure_exits_nonzero(runner, valid_token):
    result = invoke(runner, valid_token)
    assert result.exit_code == 1


def test_audit_alg_none_exits_1(runner):
    t = make_unsigned_token({"sub": "1"})
    result = invoke(runner, t)
    assert result.exit_code == 1


# --strict


def test_strict_upgrades_warns_to_exit_1(runner):
    # An HS256 token with an otherwise acceptable exp will have at least one WARN (alg)
    t = make_token(
        {
            "sub": "1",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "x",
            "aud": "y",
            "jti": "z",
        }
    )
    default = invoke(runner, t)
    strict = invoke(runner, t, "--strict")
    assert default.exit_code == 0  # 1 WARN, no CRITICAL → grade B, exit 0 normally
    assert strict.exit_code == 1  # --strict → any WARN → exit 1


# --json schema consistency


def test_json_output_has_required_keys(runner, valid_token):
    result = invoke(runner, valid_token, "--json")
    data = json.loads(result.output)
    for key in ("schema_version", "grade", "verdict", "exit_code", "counts", "findings"):
        assert key in data, f"Missing key {key!r} in JSON output"


def test_json_error_path_has_required_keys(runner):
    # "a.b" is only two parts — guaranteed to hit the decode error path
    result = invoke(runner, "a.b", "--json")
    data = json.loads(result.output)
    assert "error" in data
    assert "message" in data
    assert result.exit_code == 2


def test_json_findings_have_required_fields(runner, valid_token):
    result = invoke(runner, valid_token, "--json")
    data = json.loads(result.output)
    for f in data["findings"]:
        assert "severity" in f
        assert "field" in f
        assert "message" in f


# --require


def test_require_upgrades_missing_iss_to_warn(runner):
    t = make_token({"sub": "1", "exp": int(time.time()) + 3600, "iat": int(time.time())})
    without = invoke(runner, t, "--json")
    with_req = invoke(runner, t, "--json", "--require", "iss")
    d_without = json.loads(without.output)
    d_with = json.loads(with_req.output)

    iss_without = next(f for f in d_without["findings"] if f["field"] == "iss")
    iss_with = next(f for f in d_with["findings"] if f["field"] == "iss")
    assert iss_without["severity"] == "INFO"
    assert iss_with["severity"] == "WARN"


# --secret adds signature verification


def test_secret_valid_shows_in_report(runner, valid_token):
    result = invoke(runner, valid_token, "--secret", "testsecret", "--json")
    data = json.loads(result.output)
    assert data["signature_valid"] is True


def test_secret_invalid_shows_in_report(runner, valid_token):
    result = invoke(runner, valid_token, "--secret", "wrongsecret", "--json")
    data = json.loads(result.output)
    assert data["signature_valid"] is False


# --public-key adds signature verification for asymmetric tokens


def _asymmetric_token_for_audit(alg: str, private_pem: bytes) -> str:
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "1", "exp": 9999999999, "iat": 1, "iss": "x", "aud": "y", "jti": "z"}
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = sign_asymmetric(h, p, private_pem, alg)
    return f"{h}.{p}.{sig}"


def test_public_key_valid_shows_in_report(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    token = _asymmetric_token_for_audit("RS256", kp.private_pem)
    result = invoke(runner, token, "--public-key", str(pub), "--json")
    data = json.loads(result.output)
    assert data["signature_valid"] is True


def test_public_key_wrong_key_shows_in_report(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    other_pub = (
        rsa.generate_private_key(65537, 2048)
        .public_key()
        .public_bytes(_s.Encoding.PEM, _s.PublicFormat.SubjectPublicKeyInfo)
    )
    pub = tmp_path / "pub.pem"
    pub.write_bytes(other_pub)
    token = _asymmetric_token_for_audit("RS256", kp.private_pem)
    result = invoke(runner, token, "--public-key", str(pub), "--json")
    data = json.loads(result.output)
    assert data["signature_valid"] is False


def test_audit_rejects_both_secret_and_public_key(runner, tmp_path, keypair_for, valid_token):
    kp = keypair_for("RS256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    result = invoke(runner, valid_token, "--secret", "x", "--public-key", str(pub))
    assert result.exit_code == 2
