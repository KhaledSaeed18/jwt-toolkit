import json

import pytest

from jwt_toolkit.cli import cli
from jwt_toolkit.core.crypto import verify_signature
from jwt_toolkit.core.decoder import decode_token


def invoke(runner, *args):
    return runner.invoke(cli, ["sign", *args])


# Happy path


def test_sign_produces_three_part_token(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "mysecret")
    assert result.exit_code == 0
    parts = result.output.strip().split(".")
    assert len(parts) == 3


def test_sign_token_is_verifiable(runner):
    result = invoke(runner, "--payload", '{"sub":"1","exp":9999999999}', "--secret", "mysecret")
    token = result.output.strip()
    decoded = decode_token(token)
    assert verify_signature(
        decoded.header_b64, decoded.payload_b64, decoded.signature, "mysecret", "HS256"
    )


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_sign_all_alg_variants(runner, alg):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--alg", alg)
    assert result.exit_code == 0
    decoded = decode_token(result.output.strip())
    assert decoded.header["alg"] == alg


# --header override
def test_sign_custom_header_overrides_alg(runner):
    custom_header = json.dumps({"alg": "HS512", "typ": "JWT", "kid": "my-key"})
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", custom_header)
    assert result.exit_code == 0
    decoded = decode_token(result.output.strip())
    assert decoded.header["alg"] == "HS512"
    assert decoded.header["kid"] == "my-key"


# Input validation


def test_sign_invalid_payload_json_exits_2(runner):
    result = invoke(runner, "--payload", "{not-json}", "--secret", "s")
    assert result.exit_code == 2


def test_sign_invalid_header_json_exits_2(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", "{not-json}")
    assert result.exit_code == 2


def test_sign_empty_secret_exits_2(runner):
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "")
    assert result.exit_code == 2


def test_sign_unsupported_alg_in_header_exits_2(runner):
    custom_header = json.dumps({"alg": "RS256", "typ": "JWT"})
    result = invoke(runner, "--payload", '{"sub":"1"}', "--secret", "s", "--header", custom_header)
    assert result.exit_code == 2
