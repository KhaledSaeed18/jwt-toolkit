import json

from jwt_toolkit.cli import cli
from jwt_toolkit.core.encoding import base64url_encode
from tests.helpers import make_token


def invoke(runner, *args, **kwargs):
    return runner.invoke(cli, ["diff", *args], **kwargs)


def test_identical_tokens_exit_0(runner):
    token = make_token({"sub": "1"})
    result = invoke(runner, token, token)
    assert result.exit_code == 0
    assert "Tokens are identical" in result.output
    assert "Neither token was verified" in result.output


def test_changed_tokens_list_fields_and_exit_0(runner):
    result = invoke(runner, make_token({"sub": "1"}), make_token({"sub": "2", "role": "x"}))
    assert result.exit_code == 0
    assert "Tokens differ" in result.output
    assert "/sub" in result.output
    assert "/role" in result.output
    assert "Signature     : changed" in result.output


def test_exit_code_flag_signals_differences(runner):
    token = make_token({"sub": "1"})
    assert invoke(runner, token, token, "--exit-code").exit_code == 0
    assert invoke(runner, token, make_token({"sub": "2"}), "--exit-code").exit_code == 1


def test_token_values_are_not_rendered_as_markup(runner):
    result = invoke(runner, make_token({"name": "[bold]x"}), make_token({"name": "y"}))
    assert result.exit_code == 0
    assert '"[bold]x"' in result.output


def test_json_shape(runner):
    result = invoke(
        runner,
        make_token({"sub": "1", "old": True}),
        make_token({"sub": "2", "new": [1]}),
        "--json",
    )
    assert result.exit_code == 0
    document = json.loads(result.output)
    assert document["schema_version"] == "0.1"
    assert document["verified"] is False
    assert document["identical"] is False
    assert document["signature_changed"] is True
    assert document["header_encoding_changed"] is False
    assert document["payload_encoding_changed"] is False
    assert document["changes"] == [
        {
            "section": "payload",
            "path": "/sub",
            "change": "changed",
            "notable": True,
            "before": "1",
            "after": "2",
        },
        {
            "section": "payload",
            "path": "/old",
            "change": "removed",
            "notable": False,
            "before": True,
        },
        {
            "section": "payload",
            "path": "/new",
            "change": "added",
            "notable": False,
            "after": [1],
        },
    ]


def test_json_identical(runner):
    token = make_token({"sub": "1"})
    document = json.loads(invoke(runner, token, token, "--json").output)
    assert document["identical"] is True
    assert document["changes"] == []


def test_reads_one_token_from_stdin_and_one_from_file(runner, tmp_path):
    path = tmp_path / "after.jwt"
    path.write_text(make_token({"sub": "2"}) + "\n")
    result = invoke(runner, "-", f"@{path}", "--json", input=make_token({"sub": "1"}))
    assert result.exit_code == 0
    assert [c["path"] for c in json.loads(result.output)["changes"]] == ["/sub"]


def test_both_tokens_from_stdin_is_rejected(runner):
    result = invoke(runner, "-", "-", "--json", input="")
    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == "stdin_conflict"


def test_malformed_input_names_the_side(runner):
    result = invoke(runner, make_token({"sub": "1"}), "not-a-token", "--json")
    assert result.exit_code == 2
    document = json.loads(result.output)
    assert document["error"] == "invalid_structure"
    assert document["input"] == "after"


def test_malformed_input_human_output(runner):
    result = invoke(runner, "not-a-token", make_token({"sub": "1"}))
    assert result.exit_code == 2
    assert "Before token" in result.output


def test_command_listed_in_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert "diff" in result.output


def test_serialization_only_change_is_explained(runner):
    token = make_token({"a": 1, "b": 2})
    header, _, signature = token.split(".")
    reordered = base64url_encode(json.dumps({"b": 2, "a": 1}).encode())
    result = invoke(runner, token, f"{header}.{reordered}.{signature}")
    assert result.exit_code == 0
    assert "Payload JSON is the same but encoded differently" in result.output
    assert "Signature     : unchanged" in result.output
