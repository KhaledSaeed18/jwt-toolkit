import json

from jwt_toolkit.cli import cli
from tests.helpers import make_token


def invoke(runner, *args):
    return runner.invoke(cli, ["decode", *args])


# Happy path


def test_decode_shows_header_and_payload(runner, valid_token):
    result = invoke(runner, valid_token)
    assert result.exit_code == 0
    assert "Header" in result.output
    assert "Payload" in result.output
    assert "Signature" in result.output


def test_decode_payload_content_visible(runner):
    t = make_token({"sub": "alice", "role": "admin"})
    result = invoke(runner, t)
    assert "alice" in result.output
    assert "admin" in result.output


# --json output


def test_decode_json_output_schema(runner, valid_token):
    result = invoke(runner, valid_token, "--json")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "0.1"
    assert "header" in data
    assert "payload" in data
    assert "signature" in data


def test_decode_json_header_fields(runner):
    t = make_token({"sub": "1"}, alg="HS384")
    result = invoke(runner, t, "--json")
    data = json.loads(result.output)
    assert data["header"]["alg"] == "HS384"
    assert data["header"]["typ"] == "JWT"


# stdin


def test_decode_reads_from_stdin(runner, valid_token):
    result = runner.invoke(cli, ["decode", "-"], input=valid_token + "\n")
    assert result.exit_code == 0
    assert "Header" in result.output


# Error paths


def test_decode_malformed_token_exits_2(runner):
    result = invoke(runner, "not.valid!!!")
    assert result.exit_code == 2


def test_decode_one_part_exits_2(runner):
    result = invoke(runner, "onlyone")
    assert result.exit_code == 2


# Time claims


def test_time_claims_are_shown_in_utc_and_relative(runner, monkeypatch):
    monkeypatch.setattr("jwt_toolkit.commands.decode.time.time", lambda: 1_700_000_000)
    token = make_token({"iat": 1_700_000_000 - 120, "exp": 1_700_000_900})
    result = invoke(runner, token)
    assert result.exit_code == 0
    assert "Time Claims" in result.output
    assert "2023-11-14 22:28:20 UTC" in result.output
    assert "in 15m" in result.output
    assert "2m ago" in result.output
    assert "not checked against a key" in result.output


def test_time_claims_table_is_omitted_without_time_claims(runner):
    result = invoke(runner, make_token({"sub": "1"}))
    assert result.exit_code == 0
    assert "Time Claims" not in result.output


def test_invalid_time_claim_is_reported_without_crashing(runner):
    result = invoke(runner, make_token({"exp": "[red]tomorrow", "nbf": 10**20}))
    assert result.exit_code == 0
    assert '"[red]tomorrow"' in result.output
    assert "not a NumericDate" in result.output
    assert "outside the range" in result.output


def test_json_output_has_no_display_fields(runner):
    result = invoke(runner, make_token({"exp": 1_700_000_900}), "--json")
    document = json.loads(result.output)
    assert document["payload"] == {"exp": 1_700_000_900}
    assert set(document) == {"schema_version", "header", "payload", "signature"}
