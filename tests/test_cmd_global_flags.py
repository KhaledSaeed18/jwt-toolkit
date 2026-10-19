import os

from jwt_toolkit.cli import cli
from tests.helpers import make_token


def test_quiet_keeps_the_generated_secret(runner):
    result = runner.invoke(cli, ["--quiet", "generate-secret"])
    assert result.exit_code == 0
    assert "Generated Secret" in result.stdout


def test_quiet_keeps_decode_output(runner, valid_token):
    result = runner.invoke(cli, ["--quiet", "decode", valid_token])
    assert result.exit_code == 0
    assert "Payload" in result.stdout


def test_quiet_keeps_verify_verdict(runner, valid_token):
    result = runner.invoke(cli, ["--quiet", "verify", valid_token, "--secret", "wrong"])
    assert result.exit_code == 1
    assert "INVALID" in result.stdout


def test_quiet_still_reports_errors(runner):
    result = runner.invoke(cli, ["--quiet", "decode", "not-a-token"])
    assert result.exit_code == 2
    assert "Invalid JWT structure" in result.stderr


def test_quiet_drops_crack_status_lines(runner, tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("nope\n")
    token = make_token({"sub": "1"})
    result = runner.invoke(cli, ["--quiet", "crack", token, str(wordlist), "--workers", "1"])
    assert result.exit_code == 0
    assert "Algorithm :" not in result.output
    assert "Secret not found" in result.stdout


def test_crack_status_lines_shown_without_quiet(runner, tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("nope\n")
    result = runner.invoke(cli, ["crack", make_token({"sub": "1"}), str(wordlist)])
    assert "Algorithm :" in result.stdout


def test_error_panels_go_to_stderr(runner):
    result = runner.invoke(cli, ["sign", "--payload", "not json", "--secret", "x"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Invalid payload JSON" in result.stderr


def test_json_errors_stay_on_stdout(runner):
    result = runner.invoke(cli, ["decode", "not-a-token", "--json"])
    assert result.exit_code == 2
    assert '"error": "invalid_structure"' in result.stdout


def test_global_flags_do_not_leak_into_the_environment(runner, valid_token, monkeypatch):
    monkeypatch.delenv("JWT_TOOLKIT_QUIET", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    runner.invoke(cli, ["--quiet", "--no-color", "decode", valid_token])
    assert "JWT_TOOLKIT_QUIET" not in os.environ
    assert "NO_COLOR" not in os.environ
