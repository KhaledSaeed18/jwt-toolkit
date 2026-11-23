import json

import pytest

from jwt_toolkit.cli import cli
from jwt_toolkit.core.decoder import MAX_TOKEN_BYTES
from tests.helpers import TEST_SECRET, make_token

_OVERSIZED = "a" * (MAX_TOKEN_BYTES + 1)


def _wrapped(token: str) -> str:
    return token[:20] + "\n" + token[20:]


@pytest.mark.parametrize("command", ["decode", "audit", "forge", "crack"])
def test_oversized_argument_is_rejected(runner, command):
    result = runner.invoke(cli, [command, _OVERSIZED, "--json"])
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "token_too_large"


def test_oversized_stdin_is_rejected(runner):
    result = runner.invoke(cli, ["decode", "-", "--json"], input=_OVERSIZED)
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "token_too_large"


def test_oversized_file_is_rejected(runner, tmp_path):
    path = tmp_path / "big.jwt"
    path.write_text(_OVERSIZED)
    result = runner.invoke(cli, ["decode", f"@{path}", "--json"])
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "token_too_large"


def test_token_file_with_surrounding_newlines_still_works(runner, tmp_path):
    path = tmp_path / "t.jwt"
    path.write_text(f"\n{make_token({'sub': '1'})}\n")
    result = runner.invoke(cli, ["decode", f"@{path}", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["payload"] == {"sub": "1"}


def test_decode_tolerates_embedded_whitespace_and_warns(runner):
    result = runner.invoke(cli, ["decode", _wrapped(make_token({"sub": "1"})), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["payload"] == {"sub": "1"}
    assert "Whitespace inside the token was removed" in result.stderr


def test_decode_warning_is_dropped_under_quiet(runner):
    result = runner.invoke(cli, ["--quiet", "decode", _wrapped(make_token({"sub": "1"}))])
    assert result.exit_code == 0
    assert "Whitespace" not in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["verify", "--secret", TEST_SECRET],
        ["audit"],
        ["forge"],
    ],
)
def test_other_commands_reject_embedded_whitespace(runner, args):
    token = _wrapped(make_token({"sub": "1"}))
    result = runner.invoke(cli, [args[0], token, *args[1:], "--json"])
    assert result.exit_code == 2
    document = json.loads(result.output)
    assert (document["error"], document["cause"]) == ("invalid_structure", "embedded_whitespace")


def test_diff_keeps_the_cause_and_names_the_side(runner):
    token = make_token({"sub": "1"})
    result = runner.invoke(cli, ["diff", token, _wrapped(token), "--json"])
    assert result.exit_code == 2
    document = json.loads(result.output)
    assert document["cause"] == "embedded_whitespace"
    assert document["input"] == "after"


def test_sign_rejects_a_duplicate_claim(runner):
    result = runner.invoke(
        cli, ["sign", "--payload", '{"sub":"a","sub":"b"}', "--secret", TEST_SECRET]
    )
    assert result.exit_code == 2
    assert "appears twice" in result.output


def test_sign_rejects_payload_nested_too_deep(runner):
    payload = '{"x":' + "[" * 40 + "]" * 40 + "}"
    result = runner.invoke(cli, ["sign", "--payload", payload, "--secret", TEST_SECRET])
    assert result.exit_code == 2
    assert "nested deeper" in result.output
