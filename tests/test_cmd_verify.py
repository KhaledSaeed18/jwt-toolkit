import json
import time

from jwt_toolkit.cli import cli
from tests.helpers import make_rs256_token, make_token, make_unsigned_token


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
