import json
import time

from cryptography.hazmat.primitives import serialization as _s
from cryptography.hazmat.primitives.asymmetric import rsa

from jwt_toolkit.cli import cli
from jwt_toolkit.core.crypto import sign_asymmetric
from jwt_toolkit.core.encoding import base64url_encode
from tests.helpers import TEST_SECRET, make_token, make_unsigned_token


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


def test_require_sub_flags_a_missing_sub_and_fails_strict(runner):
    t = make_token({"exp": int(time.time()) + 3600, "iat": int(time.time())})
    result = invoke(runner, t, "--json", "--strict", "--require", "sub")
    assert result.exit_code == 1
    sub = next(f for f in json.loads(result.output)["findings"] if f["field"] == "sub")
    assert sub["severity"] == "WARN"


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


def test_audit_conflicting_keys_is_json_under_json_flag(runner, tmp_path, keypair_for, valid_token):
    pem = tmp_path / "key.pem"
    pem.write_bytes(keypair_for("RS256").public_pem)
    result = runner.invoke(
        cli, ["audit", valid_token, "--secret", "s", "--public-key", str(pem), "--json"]
    )
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "invalid_key_options"


def test_secret_file_adds_signature_check(runner, tmp_path):
    path = tmp_path / "secret"
    path.write_text(TEST_SECRET + "\n")
    result = invoke(runner, make_token({"sub": "1"}), "--secret-file", str(path), "--json")
    assert json.loads(result.output)["signature_valid"] is True


def test_secret_file_conflict_with_secret(runner, tmp_path):
    path = tmp_path / "secret"
    path.write_text(TEST_SECRET)
    result = invoke(
        runner, make_token({"sub": "1"}), "--secret", "x", "--secret-file", str(path), "--json"
    )
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "invalid_key_options"


def test_non_ascii_signature_with_secret_reports_invalid(runner, valid_token):
    header, payload, _ = valid_token.split(".")
    result = invoke(runner, f"{header}.{payload}.abcé", "--secret", "testsecret", "--json")
    assert result.exit_code == 1
    assert json.loads(result.stdout)["signature_valid"] is False


def test_common_secret_fails_the_audit(runner):
    token = make_token({"sub": "1"}, secret="supersecret")
    result = invoke(runner, token, "--secret", "supersecret", "--json")
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["grade"] == "F"
    secret_findings = [f for f in document["findings"] if f["field"] == "secret"]
    assert {f["severity"] for f in secret_findings} == {"CRITICAL", "WARN"}
    assert "supersecret" not in result.stdout


def test_strong_secret_passes_the_key_check(runner):
    secret = "k" * 40 + "-unlikely-to-be-in-any-list"
    token = make_token({"sub": "1"}, secret=secret)
    document = json.loads(invoke(runner, token, "--secret", secret, "--json").stdout)
    assert {"severity": "PASS", "field": "secret"}.items() <= next(
        f for f in document["findings"] if f["field"] == "secret"
    ).items()


def test_secret_that_does_not_verify_is_not_judged(runner):
    token = make_token({"sub": "1"}, secret="supersecret")
    document = json.loads(invoke(runner, token, "--secret", "other", "--json").stdout)
    assert not [f for f in document["findings"] if f["field"] == "secret"]


def test_small_rsa_key_fails_the_audit(runner, tmp_path):
    private = rsa.generate_private_key(65537, 1024)
    pem = private.private_bytes(_s.Encoding.PEM, _s.PrivateFormat.PKCS8, _s.NoEncryption())
    public = tmp_path / "small.pub"
    public.write_bytes(
        private.public_key().public_bytes(_s.Encoding.PEM, _s.PublicFormat.SubjectPublicKeyInfo)
    )
    header = base64url_encode(b'{"alg":"RS256","typ":"JWT"}')
    payload = base64url_encode(json.dumps({"exp": int(time.time()) + 300}).encode())
    signature = sign_asymmetric(header, payload, pem, "RS256")
    result = invoke(
        runner, f"{header}.{payload}.{signature}", "--public-key", str(public), "--json"
    )
    document = json.loads(result.stdout)
    assert document["grade"] == "F"
    assert any(f["field"] == "key" and f["severity"] == "CRITICAL" for f in document["findings"])


def test_stripped_signature_fails_the_audit(runner):
    header, payload, _ = make_token({"sub": "1"}).split(".")
    result = invoke(runner, f"{header}.{payload}.", "--json")
    assert result.exit_code == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(f["field"] == "signature" and f["severity"] == "CRITICAL" for f in findings)


def _b64_int(value: int) -> str:
    return base64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _jwks_url(tmp_path, private, *, kid: str) -> str:
    numbers = private.public_key().public_numbers()
    jwks = {
        "keys": [{"kty": "RSA", "kid": kid, "n": _b64_int(numbers.n), "e": _b64_int(numbers.e)}]
    }
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(jwks))
    return path.as_uri()


def _rs256_with_kid(private, kid: str) -> str:
    pem = private.private_bytes(_s.Encoding.PEM, _s.PrivateFormat.PKCS8, _s.NoEncryption())
    header = base64url_encode(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    payload = base64url_encode(json.dumps({"exp": int(time.time()) + 300}).encode())
    return f"{header}.{payload}.{sign_asymmetric(header, payload, pem, 'RS256')}"


def test_audit_verifies_the_signature_against_a_jwks(runner, tmp_path):
    private = rsa.generate_private_key(65537, 2048)
    url = _jwks_url(tmp_path, private, kid="k1")
    document = json.loads(
        invoke(runner, _rs256_with_kid(private, "k1"), "--jwks-url", url, "--json").stdout
    )
    assert document["signature_valid"] is True
    assert document["signature_detail"] == "Signature is valid"


def test_audit_reports_a_jwks_without_the_tokens_kid(runner, tmp_path):
    private = rsa.generate_private_key(65537, 2048)
    url = _jwks_url(tmp_path, private, kid="other")
    result = invoke(runner, _rs256_with_kid(private, "k1"), "--jwks-url", url, "--json")
    document = json.loads(result.stdout)
    assert result.exit_code == 1
    assert document["signature_valid"] is False
    assert document["signature_detail"].startswith("Cannot verify: No JWKS key matches kid=")


def test_audit_judges_a_weak_key_served_by_the_jwks(runner, tmp_path):
    private = rsa.generate_private_key(65537, 1024)
    url = _jwks_url(tmp_path, private, kid="k1")
    document = json.loads(
        invoke(runner, _rs256_with_kid(private, "k1"), "--jwks-url", url, "--json").stdout
    )
    assert document["grade"] == "F"
    assert any(f["field"] == "key" and f["severity"] == "CRITICAL" for f in document["findings"])


def test_audit_takes_one_key_source(runner, tmp_path, valid_token):
    result = invoke(runner, valid_token, "--secret", "x", "--jwks-url", "file:///x", "--json")
    assert result.exit_code == 2
    assert json.loads(result.stdout)["message"] == (
        "Pass only one of --secret, --public-key, or --jwks-url"
    )


def test_audit_signature_check_with_an_unverifiable_alg(runner):
    token = make_token({"sub": "1"}, header_override={"alg": "hs256", "typ": "JWT"})
    document = json.loads(invoke(runner, token, "--secret", TEST_SECRET, "--json").stdout)
    assert document["signature_valid"] is False
    assert document["signature_detail"] == "Cannot verify: Unsupported algorithm: hs256"


def test_audit_hmac_token_with_a_public_key_asks_for_the_secret(runner, tmp_path, valid_token):
    public = tmp_path / "key.pub"
    public.write_bytes(
        rsa.generate_private_key(65537, 2048)
        .public_key()
        .public_bytes(_s.Encoding.PEM, _s.PublicFormat.SubjectPublicKeyInfo)
    )
    document = json.loads(invoke(runner, valid_token, "--public-key", str(public), "--json").stdout)
    assert document["signature_valid"] is False
    assert document["signature_detail"] == (
        "HS256 requires --secret or --secret-file to verify the signature"
    )
